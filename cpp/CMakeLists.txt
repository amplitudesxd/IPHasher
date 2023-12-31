cmake_minimum_required(VERSION 3.23)
project(iphasher_cpp)

set(CMAKE_CXX_STANDARD 23)

# only supporting x86 64-bit and armv8-a right now
if (MSVC)
    # some of these flags are probably unnecessary but why not
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /O2 /Ot /GT /GL /fp:fast /Ob2 /Oi /Gy /MD /Qpar")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /O2 /Ot /GT /GL /fp:fast /Ob2 /Oi /Gy /MD /Qpar")

    if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /arch:AVX2")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /arch:AVX2")
    else ()
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /arch:ARM64")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /arch:ARM64")
    endif ()
elseif (GNU OR Clang)
    if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -msse4 -msha -O3")
    else ()
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8-a+crc+crypto -O3")
    endif ()

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
endif ()

add_executable(iphasher_cpp
        main.cpp
        hash/sha256.h
        hash/sha256-arm.c
        hash/sha256-x86.c)
