#include "pch.h"
#include <botan/hash.h>

constexpr uint32_t min = 0x00000000;
constexpr uint32_t max = 0xFFFFFFFF;
constexpr uint64_t total = max - min;
constexpr uint8_t dot = '.';

using namespace std::chrono_literals;

class Uh {
    unsigned char size7[7] = { 0 };
    unsigned char size8[8] = { 0 };
    unsigned char size9[9] = { 0 };
    unsigned char size10[10] = { 0 };
    unsigned char size11[11] = { 0 };
    unsigned char size12[12] = { 0 };
    unsigned char size13[13] = { 0 };
    unsigned char size14[14] = { 0 };
    unsigned char size15[15] = { 0 };

public:

    unsigned char* get(const int size) {
        switch (size) {
        case 7:
            return size7;
        case 8:
            return size8;
        case 9:
            return size9;
        case 10:
            return size10;
        case 11:
            return size11;
        case 12:
            return size12;
        case 13:
            return size13;
        case 14:
            return size14;
        case 15:
            return size15;
        default:
            return size15;
        }
    }
};


class Solver {
    std::unique_ptr<Botan::HashFunction> hash_ = Botan::HashFunction::create("SHA-256");

    const unsigned int id_;
    const unsigned long start_;
    const unsigned long end_;
    const unsigned char* bytes_;
    const std::vector<std::string> lookup_;
    unsigned char hash_data_[32];

    // copium
    Uh container_{};

    unsigned long* global_progress_;

    bool& running_;

public:

    Solver(const unsigned int& id, bool& running, unsigned long* global_progress, std::vector<std::string> lookup, const unsigned char* bytes, const unsigned long& start, const unsigned long& end) :
	id_(id), start_(start), end_(end), bytes_(bytes), lookup_(lookup), global_progress_(global_progress), running_(running) {}

    void run() {
        for (unsigned long addr = start_; addr < end_; addr++)
        {
            if (!running_) break;
            const unsigned int n1 = (addr >> 24) & 0xff;
            const unsigned int n2 = (addr >> 16) & 0xff;
            const unsigned int n3 = (addr >> 8) & 0xff;
            const unsigned int n4 = addr & 0xff;

            uint8_t n1s = 1;
            if (n1 >= 100) n1s += 2;
            else if (n1 >= 10) n1s++;
            uint8_t n2s = 1;
            if (n2 >= 100) n2s += 2;
            else if (n1 >= 10) n2s++;
            uint8_t n3s = 1;
            if (n3 >= 100) n3s += 2;
            else if (n3 >= 10) n3s++;
            uint8_t n4s = 1;
            if (n4 >= 100) n4s += 2;
            else if (n4 >= 10) n4s++;

            const uint8_t size = 3 + n1s + n2s + n3s + n4s;

            const auto data = container_.get(size);
            uint8_t i = 0;
            memcpy(data + i, (lookup_.data() + n1)->c_str(), n1s);
            i += n1s;
            data[i++] = dot;
            memcpy(data + i, (lookup_.data() + n2)->c_str(), n2s);
            i += n2s;
            data[i++] = dot;
            memcpy(data + i, (lookup_.data() + n3)->c_str(), n3s);
            i += n3s;
            data[i++] = dot;
            memcpy(data + i, (lookup_.data() + n4)->c_str(), n4s);
            
            hash(data, size, hash_data_);
            
            if (std::memcmp(bytes_, hash_data_, 32) == 0) {
                running_ = false;
                std::cout << " * Found: " << data << std::endl;
                break;
            }

            global_progress_[id_]++;
        }
    }

	void hash(const unsigned char* source, const int& src_len, unsigned char* dist) const {
        hash_->clear();
        hash_->update(source, src_len);
        hash_->final(dist);
    }
};

class comma_numpunct : public std::numpunct<char>
{
protected:
	char do_thousands_sep() const override
	{
        return ',';
    }

    std::string do_grouping() const override
    {
        return "\03";
    }
};

int main(const int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "You must provide a SHA-256 hash (hex format)!" << std::endl;
        return -1;
    }

    std::vector<std::string> lookup{256};
    for (int i = 0; i < 256; i++)
    {
        lookup.push_back(std::to_string(i));
    }

    const unsigned int thread_count = 12;//std::thread::hardware_concurrency();

    std::cout << "Looking for hash: " << argv[1] << std::endl;
    std::cout << "threads: " << thread_count << std::endl;

    std::vector<Solver*> solvers;
    std::vector<std::thread> thread_list;
    bool running = true;
    unsigned long progress_holder[thread_count];
    for (unsigned long& i : progress_holder) i = 0;

    unsigned char data[32];
    int j = 0;
    for (int i = 0; i < std::strlen(argv[1]); i += 2) {
        std::string str(argv[1] + i, argv[1] + i + 2);
        std::istringstream iss(str);
        int res;
        iss >> std::hex >> res;
        data[j++] = res;
    }

    unsigned long ip = min;
    constexpr unsigned long step = (total + 2) / thread_count;

    for (unsigned int i = 0; i < thread_count; i++) {
        const unsigned long start = ip;
        const unsigned long end = ip + step;

        Solver* solver = new Solver(i, running, progress_holder, lookup, data, start, end);
        solvers.push_back(solver);

        std::thread t = std::thread(&Solver::run, solver);
        thread_list.push_back(move(t));
        ip += step;
    }

    std::thread monitor([&running, &progress_holder, &thread_count]() {
        const auto start = std::chrono::system_clock::now();

        const std::locale commas(std::locale(), new comma_numpunct());
        std::cout.imbue(commas);
        while (running) {
            std::this_thread::sleep_for(5s);
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - start);

            uint64_t global = 0;
            for (const unsigned long i : progress_holder) global += i;
            auto ipps = global / (elapsed.count() / static_cast<double>(1000));
            const double eta = (total - global) / ipps;
            std::cout << global << "/" << max << " IPs | " << std::fixed << std::setprecision(2) << ipps << " IPs/sec | Progress: " << (global / static_cast<double>(max)) * 100 << "% | ETA: " << eta << "s | Elapsed: " << elapsed.count() / 1000 << "s" << std::endl;
        }
        });
    monitor.join();
}
