#include "hash/sha256.h"

#include <emmintrin.h>
#include <future>

#include <cstring>
#include <atomic>
#include <thread>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>

#define DIGEST_LENGTH 32
#define MESSAGE_BLOCK_LENGTH 64

#define PROGRESS_INCREMENT 10000000

#if defined(__x86_64__) || defined(_M_X64) || \
    defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
#define ARCH_X86
#elif defined(__ARM_ARCH_ISA_A64) && !defined(HASH_STD)
#define ARCH_ARM
#else
#error "Unsupported architecture"
#endif

namespace {

	class comma_numpunct : public std::numpunct<char> {
	protected:
		[[nodiscard]] char do_thousands_sep() const override {
			return ',';
		}

		[[nodiscard]] std::string do_grouping() const override {
			return "\03";
		}
	};

	std::atomic<bool> completed(false);

	// thanks SO
	std::vector<unsigned char> from_hex(const std::string &hex) {
		std::vector<unsigned char> bytes;
		for (unsigned int i = 0; i < hex.length(); i += 2) {
			std::string byteString = hex.substr(i, 2);
			char byte = (char) strtol(byteString.c_str(), nullptr, 16);
			bytes.push_back(byte);
		}
		return bytes;
	}

	// thanks SO
	std::string to_hex(unsigned char *data, std::uint64_t len) {
		std::stringstream ss;
		ss << std::hex;

		for (int i = 0; i < len; i++)
			ss << std::setw(2) << std::setfill('0') << (int) data[i];

		return ss.str();
	}

	void solve_range(
			const char *TABLE[256],
			const unsigned char *target,
			std::uint64_t start,
			std::uint64_t end,
			std::atomic_uint32_t *progress) {

		constexpr uint32_t BASE_SHA_STATE[8] = {
				0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
				0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
		};

		unsigned char data[MESSAGE_BLOCK_LENGTH];
		int nums[4];

		unsigned char digest[DIGEST_LENGTH];
		uint32_t sha_state[8];

		for (std::uint64_t address = start; address < end; address++) {
			if (completed)
				return;

			nums[0] = (unsigned char) (address >> 24) & 0xFF;
			nums[1] = (unsigned char) (address >> 16) & 0xFF;
			nums[2] = (unsigned char) (address >> 8) & 0xFF;
			nums[3] = (unsigned char) address & 0xFF;

			int idx = 0;

			// process the octets without looping results in a minor speedup (although ugly)
			const char* d = TABLE[nums[0]];

			if (d[2]) {
				data[idx++] = d[0];
				data[idx++] = d[1];
				data[idx++] = d[2];
			} else if (d[1]) {
				data[idx++] = d[0];
				data[idx++] = d[1];
			} else {
				data[idx++] = d[0];
			}

			data[idx++] = '.';
			d = TABLE[nums[1]];

			if (d[2]) {
				data[idx++] = d[0];
				data[idx++] = d[1];
				data[idx++] = d[2];
			} else if (d[1]) {
				data[idx++] = d[0];
				data[idx++] = d[1];
			} else {
				data[idx++] = d[0];
			}

			data[idx++] = '.';
			d = TABLE[nums[2]];

			if (d[2]) {
				data[idx++] = d[0];
				data[idx++] = d[1];
				data[idx++] = d[2];
			} else if (d[1]) {
				data[idx++] = d[0];
				data[idx++] = d[1];
			} else {
				data[idx++] = d[0];
			}

			data[idx++] = '.';
			d = TABLE[nums[3]];

			if (d[2]) {
				data[idx++] = d[0];
				data[idx++] = d[1];
				data[idx++] = d[2];
			} else if (d[1]) {
				data[idx++] = d[0];
				data[idx++] = d[1];
			} else {
				data[idx++] = d[0];
			}

			// block padding
			data[idx] = 0x80;

			std::uint32_t total_len = idx + 1;
			total_len += 56 - total_len;

			memset(data + idx + 1, 0, total_len);

			std::uint64_t bit_len = idx * 8;

			for (int i = 0; i < 8; ++i) {
				data[total_len + 7 - i] = bit_len >> i * 8 & 0xFF;
			}

			// reset sha state
			memcpy(sha_state, BASE_SHA_STATE, sizeof(BASE_SHA_STATE));

			// IPs will fit in 1 block (:
#ifdef ARCH_X86
			sha256_process_x86(sha_state, data);
			sha256_final_x86(sha_state, digest);
#else
			sha256_process_arm(sha_state, data, MESSAGE_BLOCK_LENGTH);

			for (int i = 0; i < 8; ++i) {
				digest[i * 4] = (sha_state[i] >> 24) & 0xff;
				digest[i * 4 + 1] = (sha_state[i] >> 16) & 0xff;
				digest[i * 4 + 2] = (sha_state[i] >> 8) & 0xff;
				digest[i * 4 + 3] = sha_state[i] & 0xff;
			}
#endif

			// not 100% accurate as we only compare the first 10 bytes of the hash (more efficient and should work fine)
			if (memcmp(digest, target, 10) == 0) {
				completed = true;
				data[idx] = '\0';

				std::this_thread::sleep_for(std::chrono::seconds(1)); // i cba c:
				std::cout << "\rFound IP: " << (char *) data << std::endl;
				return;
			}

			if (address % PROGRESS_INCREMENT == 0) {
				progress->fetch_add(PROGRESS_INCREMENT);
			}
		}
	}

}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		std::cout << "Provide a SHA256 hash bruh." << std::endl;
		return -1;
	}

	std::cout << "Brute forcing IP hash: " << argv[1] << std::endl;

	constexpr std::uint64_t MIN_IP = 0x00000000ULL;
	constexpr std::uint64_t MAX_IP = 0xFFFFFFFFULL;

	constexpr auto TOTAL = MAX_IP - MIN_IP + 2;

	const std::uint32_t THREADS = std::thread::hardware_concurrency();
	const auto STEP = TOTAL / THREADS;

	const char *TABLE[256];
	for (int i = 0; i < 256; i++) {
		TABLE[i] = new char[3];
		sprintf((char *) TABLE[i], "%d", i);
	}

	const auto target = from_hex(argv[1]);

#ifdef _MSC_VER
	// god msvc is ass
	auto *threads = new std::unique_ptr<std::thread>[THREADS];
	auto *progress = new std::atomic_uint32_t[THREADS];
#else
	std::unique_ptr<std::thread> threads[THREADS];
	std::atomic_uint32_t progress[THREADS];
#endif

	for (int i = 0; i < THREADS; i++) {
		progress[i].store(0);
	}

	auto ip = MIN_IP;
	for (std::uint32_t i = 0; i < THREADS; i++) {
		auto start = ip;
		auto end = ip + STEP;

		threads[i] = std::make_unique<std::thread>(solve_range, TABLE, target.data(), start, end, &progress[i]);

		ip += STEP;
	}

	const auto start = std::chrono::high_resolution_clock::now();

	const std::locale commas(std::locale(), new comma_numpunct());
	std::cout.imbue(commas);

	while (!completed) {
		std::this_thread::sleep_for(std::chrono::seconds(1));

		if (completed)
			break;

		auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);

		uint64_t global = 0;
		for (int i = 0; i < THREADS; i++) {
			global += progress[i].load();
		}

		double ips_per_second = (double) global / ((double) elapsed.count() / 1000.0);
		double eta = ((double) TOTAL - (double) global) / ips_per_second;

		std::cout << '\r' << global << '/' << MAX_IP << " IPs | " << std::fixed << std::setprecision(2) << ips_per_second
		          << " IPs/sec | Progress: " << ((double) global / static_cast<double>(MAX_IP)) * 100 << "% | ETA: "
		          << eta << "s | Elapsed: " << elapsed.count() / 1000 << "s\t\t" << std::flush;
	}

	std::cout << std::endl;

	auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start).count();

	std::this_thread::sleep_for(std::chrono::seconds(1));

	std::cout << "Completed in " << duration << "ms" << std::endl;

	for (int i = 0; i < THREADS; i++) {
		threads[i]->join();
	}

#ifdef _MSC_VER
	delete[] threads;
	delete[] progress;
#endif

	for (auto &i: TABLE)
		delete[] i;

	return 0;
}
