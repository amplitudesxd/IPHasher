#include "hash/hash.h"

#include <cstring>
#include <atomic>
#include <thread>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>

#define PROGRESS_INCREMENT 10000000

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

		unsigned char digest[DIGEST_LENGTH];
		unsigned char data[MESSAGE_BLOCK_LENGTH];
		int nums[4];

		for (std::uint64_t address = start; address < end; address++) {
			if (completed)
				return;

			nums[0] = (unsigned char) (address >> 24) & 0xFF;
			nums[1] = (unsigned char) (address >> 16) & 0xFF;
			nums[2] = (unsigned char) (address >> 8) & 0xFF;
			nums[3] = (unsigned char) address & 0xFF;

			int idx = 0;
			for (int i = 0; i < 4; i++) {
				if (i != 0)
					data[idx++] = '.';

				auto *d = TABLE[nums[i]];
				for (int j = 0; j < 3; j++) {
					auto c = d[j];
					if (c == '\0')
						break;

					data[idx++] = c;
				}
			}

			// block padding
			data[idx] = 0x80;

			std::uint64_t total_len = idx + 1;
			total_len += 56 - total_len;

			memset(data + idx + 1, 0, total_len);

			std::uint64_t bit_len = idx * 8;
			for (size_t i = 0; i < 8; ++i) {
				data[total_len + 7 - i] = bit_len >> i * 8 & 0xFF;
			}

			// IPs will fit in 1 block (:
			hash::sha256(data, MESSAGE_BLOCK_LENGTH, digest);

			if (memcmp(digest, target, DIGEST_LENGTH) == 0) {
				completed = true;
				data[idx] = '\0';

				std::this_thread::sleep_for(std::chrono::seconds(1)); // i cba c:
				std::cout << "\rFound IP: " << (char *) data << " (" << to_hex(digest, DIGEST_LENGTH) << ")" << std::endl;
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
