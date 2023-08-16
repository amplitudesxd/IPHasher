#include <openssl/sha.h>
#include <rocksdb/db.h>
#include <cassert>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#define MIN_IP 0x00000000u
#define MAX_IP 0xffffffffu

// #define OUTPUT_DIR "/home/inva/Data/ip-brute/"
#define OUTPUT_DIR ""

const auto NUM_CPUS = std::thread::hardware_concurrency();

template <class unit = std::chrono::milliseconds>
class profiler {
public:
    explicit profiler(std::string name, std::string suffix = "ms")
        : name(std::move(name)),
          suffix(std::move(suffix)),
          start(std::chrono::high_resolution_clock::now()) {}

    void end() {
        if (ended) {
            return;
        }

        auto delta = std::chrono::high_resolution_clock::now() - this->start;

        std::cout << name << ": "
                  << std::chrono::duration_cast<unit>(delta).count() << " "
                  << suffix << std::endl;

        ended = true;
    }

    ~profiler() { end(); }

private:
    std::string name;
    std::string suffix;

    std::chrono::high_resolution_clock::time_point start;

    bool ended = false;
};

std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256Context;

    SHA256_Init(&sha256Context);
    SHA256_Update(&sha256Context, input.c_str(), input.size());
    SHA256_Final(hash, &sha256Context);

    return {(char*)hash, SHA256_DIGEST_LENGTH};
}

std::string ip_to_string(uint32_t ip) {
    std::stringstream ip_builder;

    ip_builder << (ip >> 24 & 0xff);
    ip_builder << ".";
    ip_builder << (ip >> 16 & 0xff);
    ip_builder << ".";
    ip_builder << (ip >> 8 & 0xff);
    ip_builder << ".";
    ip_builder << (ip & 0xff);

    return ip_builder.str();
}

auto open_rocksdb() {
    rocksdb::DB* db;

    rocksdb::Options options;

    options.create_if_missing = true;
    options.compression = rocksdb::CompressionType::kZSTD;

    options.IncreaseParallelism(NUM_CPUS);
    options.OptimizeLevelStyleCompaction();

    rocksdb::Status status =
        rocksdb::DB::Open(options, OUTPUT_DIR "ip_db", &db);

    assert(status.ok());

    auto destroy = [](rocksdb::DB* db) {
        db->SyncWAL();
        db->Close();

        delete db;
    };

    return std::shared_ptr<rocksdb::DB>(db, destroy);
}

void generate_thread(std::shared_ptr<rocksdb::DB> db,
                     uint32_t start_ip,
                     uint32_t end_ip) {
    rocksdb::WriteBatch batch;
    rocksdb::WriteOptions options;

    for (uint64_t ip = start_ip; ip <= end_ip; ++ip) {
        auto ip_str = ip_to_string(ip);

        auto hash = sha256(ip_str);
        std::stringstream hex_hash_builder;
        for (auto const& c : hash) {
            hex_hash_builder << std::hex << std::setfill('0') << std::setw(2)
                             << ((unsigned int)c & 0xff);
        }

        auto hex_hash = hex_hash_builder.str();

        batch.Put(hex_hash, ip_str);

        if (batch.Count() >= (1 << 21)) {
            db->Write(options, &batch);
            batch.Clear();
        }
    }

    if (batch.Count() > 0) {
        db->Write(options, &batch);
    }
}

int generate() {
    auto db = open_rocksdb();

    {
        auto it = std::unique_ptr<rocksdb::Iterator>(
            db->NewIterator(rocksdb::ReadOptions()));

        it->SeekToFirst();
        if (it->Valid()) {
            std::cerr
                << "rocksdb isn't empty, refusing to write over existing data"
                << std::endl;

            return 1;
        }
    }

    uint32_t cpus = NUM_CPUS;
    uint64_t total_ips = MAX_IP - MIN_IP + 1ull;

    uint32_t step_size = total_ips / cpus;

    uint32_t ip = MIN_IP;

    std::vector<std::thread> threads(NUM_CPUS);

    for (int i = 0; i < NUM_CPUS; ++i) {
        auto start_ip = ip;
        auto end_ip = i == NUM_CPUS - 1 ? MAX_IP : ip + step_size - 1;

        threads[i] = std::thread(generate_thread, db, start_ip, end_ip);

        ip += step_size;
    }

    for (auto& thread : threads) {
        thread.join();
    }

    return 0;
}

int query(const char* hash) {
    auto db_open_profiler = profiler("db open");
    auto db = open_rocksdb();
    db_open_profiler.end();

    std::string value;

    auto query_profiler = profiler("query");
    auto status = db->Get(rocksdb::ReadOptions(), hash, &value);
    query_profiler.end();

    if (status.ok()) {
        std::cout << value << std::endl;

        return 0;
    }

    std::cerr << "not found" << std::endl;

    return 1;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "provide a subcommand" << std::endl;

        return 1;
    }

    auto subcommand = argv[1];

    if (!strcmp(subcommand, "query")) {
        if (argc < 3) {
            std::cerr << "provide a hash" << std::endl;

            return 1;
        }

        auto hash = argv[2];

        return query(hash);
    }

    if (!strcmp(subcommand, "generate")) {
        return generate();
    }

    std::cerr << "unknown subcommand" << std::endl;
    return 1;
}
