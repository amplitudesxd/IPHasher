#define CL_TARGET_OPENCL_VERSION 120

#include <CL/cl.h>
#include <fstream>

#include <cstring>
#include <atomic>
#include <thread>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>

// by default the kernel file is embedded on x86 builds (using objcopy)
// if you are having problems with the embedded kernel on these builds uncomment this macro
// note: if you uncomment this macro, you must place the kernel.cl file in the same directory as the executable
//#define EMBEDDED_KERNEL 0

// [DO NOT MODIFY] match first 8 bytes of the hash
#define TARGET_BYTE_MATCH 8

// Tweak GROUP_SIZE for your GPU:
// --------------------------
// reasoning for 81920 / 2:
// 3080 Ti has 80 streaming multiprocessors
// ampere is 1024 threads per SM
// 80 x 1024 = 81920
// then did / 2 as that seems to perform better with my testing
// your mileage may vary - test different values for your GPU
// --------------------------
// Recent NVIDIA GPU SMs:
// 4090     - 128
// 4080     - 76
// 4070 Ti  - 60
// 3090     - 82
// 3080 Ti  - 80
// 3080     - 68
// 3070     - 46
// 3060 Ti  - 38
// 3060     - 28
// 2080 Ti  - 68
// 2080 S   - 48
// 2080     - 46
// 2070 S   - 40
// 2070     - 36
// 2060 S   - 34
// 2060     - 30
// 1080 Ti  - 28
// --------------------------
const int GROUP_SIZE = 81920 / 2;

// enable this to run the kernel 1000 times in one execution (end early with control+c)
const bool DEBUG = false;

namespace {

	const std::uint64_t MIN_IP = 0x00000000ULL;
	const std::uint64_t MAX_IP = 0xFFFFFFFFULL;

#if EMBEDDED_KERNEL
	extern "C" uint8_t _binary_kernel_cl_start[];
	extern "C" uint8_t _binary_kernel_cl_end[];
	size_t _binary_opencl_kernel_cl_size = _binary_kernel_cl_end - _binary_kernel_cl_start;
#endif

	class comma_numpunct : public std::numpunct<char> {
	protected:
		[[nodiscard]] char do_thousands_sep() const override {
			return ',';
		}

		[[nodiscard]] std::string do_grouping() const override {
			return "\03";
		}
	};

	// thanks, SO
	std::vector<unsigned char> from_hex(const std::string &hex) {
		std::vector<unsigned char> bytes;
		for (unsigned int i = 0; i < hex.length(); i += 2) {
			std::string byteString = hex.substr(i, 2);
			char byte = (char) strtol(byteString.c_str(), nullptr, 16);
			bytes.push_back(byte);
		}
		return bytes;
	}

	void execute_range(const char *TABLE[256], const unsigned char target[TARGET_BYTE_MATCH]) {
#if EMBEDDED_KERNEL
		const char *kernel_src_str = (const char *) _binary_kernel_cl_start;
		size_t kernel_len = _binary_opencl_kernel_cl_size;
#else
		// note: if embedded kernel is not enabled, the kernel.cl file must be in the same directory as the executable
		std::ifstream kernel_file(R"(kernel.cl)");
		std::string kernel_source((std::istreambuf_iterator<char>(kernel_file)), std::istreambuf_iterator<char>());

		const char *kernel_src_str = kernel_source.c_str();
		size_t kernel_len = kernel_source.size();
#endif

#define CHECK_RET(at) if (ret != CL_SUCCESS) { std::cout << "Error at " #at ": " << ret << std::endl; }(0)

		cl_int ret;

		cl_platform_id platform;
		ret = clGetPlatformIDs(1, &platform, nullptr);
		CHECK_RET(clGetPlatformIDs);

		cl_device_id device;
		ret = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, &device, nullptr);
		CHECK_RET(clGetDeviceIDs);

		cl_context context = clCreateContext(nullptr, 1, &device, nullptr, nullptr, nullptr);

		cl_command_queue queue = clCreateCommandQueue(context, device, 0, nullptr);

		cl_program program = clCreateProgramWithSource(context, 1, &kernel_src_str, &kernel_len, nullptr);
		ret = clBuildProgram(program, 1, &device, nullptr, nullptr, nullptr);
		CHECK_RET(clBuildProgram);

		if (ret != CL_SUCCESS) {
			size_t log_size;
			clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_size);

			auto *log = new char[log_size + 1];
			memset(log, 0, log_size + 1);

			size_t length;
			clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, log_size, log, &length);
			std::cout << "Failed to build program: " << log << std::endl;

			delete[] log;

			clReleaseProgram(program);
			clReleaseCommandQueue(queue);
			clReleaseContext(context);
			return;
		}

		cl_kernel kernel = clCreateKernel(program, "sha256_range", nullptr);

		char TABLE_FLATTENED[256 * 3]; // max length of 3 per table entry
		memset(TABLE_FLATTENED, 0, 256 * 3);

		for (int i = 0; i < 256; i++) {
			strncpy(&TABLE_FLATTENED[i * 3], TABLE[i], strlen(TABLE[i]));
		}

		cl_mem table_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY, sizeof(const char *) * 256, nullptr, nullptr);
		cl_mem target_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY, TARGET_BYTE_MATCH, nullptr, nullptr);
		cl_mem result_buffer = clCreateBuffer(context, CL_MEM_WRITE_ONLY, 32, nullptr, nullptr);
		cl_mem completed_buffer = clCreateBuffer(context, CL_MEM_READ_WRITE, sizeof(cl_uint), nullptr, nullptr);
		cl_mem progress_buffer = clCreateBuffer(context, CL_MEM_READ_WRITE, sizeof(cl_uint), nullptr, nullptr);

		cl_uint target_int[TARGET_BYTE_MATCH / sizeof(cl_uint)];
		for (size_t i = 0; i < TARGET_BYTE_MATCH / sizeof(cl_uint); ++i) {
			target_int[i] =
					((cl_uint) target[i * 4 + 0] << 24) |
					((cl_uint) target[i * 4 + 1] << 16) |
					((cl_uint) target[i * 4 + 2] << 8) |
					((cl_uint) target[i * 4 + 3]);
		}

		ret = clEnqueueWriteBuffer(queue, target_buffer, CL_TRUE, 0, TARGET_BYTE_MATCH, target_int, 0, nullptr, nullptr);
		CHECK_RET(clEnqueueWriteBuffer1);

		ret = clEnqueueWriteBuffer(queue, table_buffer, CL_TRUE, 0, 256 * 3, TABLE_FLATTENED, 0, nullptr, nullptr);
		CHECK_RET(clEnqueueWriteBuffer2);

		clSetKernelArg(kernel, 0, sizeof(cl_mem), &table_buffer);
		clSetKernelArg(kernel, 1, sizeof(cl_mem), &target_buffer);
		clSetKernelArg(kernel, 2, sizeof(cl_mem), &result_buffer);
		clSetKernelArg(kernel, 3, sizeof(cl_mem), &completed_buffer);
		clSetKernelArg(kernel, 4, sizeof(cl_mem), &progress_buffer);
		clSetKernelArg(kernel, 5, sizeof(uint64_t), &MIN_IP);
		clSetKernelArg(kernel, 6, sizeof(uint64_t), &MAX_IP);

		size_t global_work_size = GROUP_SIZE;
		ret = clEnqueueNDRangeKernel(queue, kernel, 1, nullptr, &global_work_size, nullptr, 0, nullptr, nullptr);
		CHECK_RET(clEnqueueNDRangeKernel);

		const auto time = std::chrono::high_resolution_clock::now();

//		std::atomic<bool> completed(false);

		// this seems pointless right now as it finishes within a second
		// also don't think it works properly due to blocking the kernel on clEnqueueNDRangeKernel
//		auto thread = std::thread([&]() {
//			while (!completed) {
//				cl_uint progress_data;
//				clEnqueueReadBuffer(queue, progress_buffer, CL_TRUE, 0, sizeof(cl_uint), &progress_data, 0, nullptr, nullptr);
//
//				auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - time);
//
//				double ips_per_second = (double) progress_data / ((double) elapsed.count() / 1000.0);
//				double eta = ((double) (MIN_IP + MAX_IP + 2) - (double) progress_data) / ips_per_second;
//
//				std::cout << '\r' << progress_data << '/' << MAX_IP << " IPs | " << std::fixed << std::setprecision(2) << ips_per_second
//				          << " IPs/sec | Progress: " << ((double) progress_data / static_cast<double>(MAX_IP)) * 100 << "% | ETA: "
//				          << eta << "s | Elapsed: " << elapsed.count() / 1000 << "s\t\t" << std::endl;
//
//				std::this_thread::sleep_for(std::chrono::seconds(1));
//			}
//		});

		clFinish(queue);

		auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - time).count();

//		completed = true;
//		thread.join();

		char result_data[32];
		memset(result_data, 0, 32);

		ret = clEnqueueReadBuffer(queue, result_buffer, CL_TRUE, 0, 32, result_data, 0, nullptr, nullptr);
		CHECK_RET(clEnqueueReadBuffer);

		if (strlen(result_data) == 0) {
			std::cout << "Failed to find a match" << std::endl;
		} else {
			std::cout << "IP found: " << result_data << std::endl;
		}

		std::cout << "Completed in " << duration << "ms" << std::endl;

		clReleaseMemObject(result_buffer);
		clReleaseMemObject(completed_buffer);
		clReleaseMemObject(target_buffer);
		clReleaseMemObject(table_buffer);

		clReleaseKernel(kernel);
		clReleaseProgram(program);
		clReleaseCommandQueue(queue);
		clReleaseContext(context);

#undef CHECK_RET
	}

}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		std::cout << "Provide a SHA256 hash bruh." << std::endl;
		return -1;
	}

	std::cout << "Brute forcing IP hash: " << argv[1] << std::endl;

	const auto target = from_hex(argv[1]);

	const char *TABLE[256];
	for (int i = 0; i < 256; i++) {
		TABLE[i] = new char[3];
		sprintf((char *) TABLE[i], "%d", i);
	}

	unsigned char target_trim[TARGET_BYTE_MATCH];
	memcpy(target_trim, target.data(), TARGET_BYTE_MATCH);

	const std::locale commas(std::locale(), new comma_numpunct());
	std::cout.imbue(commas);

	constexpr int MAX_ITER = 1000; // debug mode just runs it 1000 times
	int itr = 0;
	do {
		execute_range(TABLE, target_trim);

		if (++itr == MAX_ITER)
			break;
	} while (DEBUG);

	for (auto &i: TABLE)
		delete[] i;

	return 0;
}
