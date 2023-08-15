cmake_minimum_required(VERSION 3.23)
project(iphasher_cpp)

set(CMAKE_CXX_STANDARD 23)

# only supporting x86 64-bit and armv8-a right now
if (MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /O2")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /O2")
elseif (GNU OR Clang)
    if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -msse4 -msha -O3")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
    else ()
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8-a+crc+crypto -O3")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
    endif ()
endif ()

add_executable(iphasher_cpp
        main.cpp
        hash/hash.h
        hash/hash_arm.cpp
        hash/hash_x86.cpp
        hash/sha256.h
        hash/sha256-arm.c
        hash/sha256-x86.c)
