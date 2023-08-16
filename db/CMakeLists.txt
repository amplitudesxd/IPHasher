cmake_minimum_required(VERSION 3.12)
project(ip-brute)

set(WITH_ZSTD ON CACHE INTERNAL "enable zstd compression in rocksdb")

add_subdirectory(rocksdb)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS_RELEASE "-Ofast")

find_package(OpenSSL REQUIRED)

add_executable(ip-brute main.cpp)

target_link_libraries(ip-brute PRIVATE OpenSSL::Crypto rocksdb)
