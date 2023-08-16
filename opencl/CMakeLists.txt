cmake_minimum_required(VERSION 3.23)
project(iphasher_opencl)

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
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
endif ()

# embedded kernel for x86 only for now
if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64")
    add_definitions(-DEMBEDDED_KERNEL=1)
    set(ADDITIONAL_OBJECTS "")

    function(binary_to_obj dir input output)
        add_custom_command(
                OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${output}.obj
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${dir}
                COMMAND objcopy --input-target binary --output-target pe-x86-64 --binary-architecture i386 ${input} ${CMAKE_CURRENT_BINARY_DIR}/${output}.obj
                COMMENT "Re-generated ${output}.obj file from ${input}"
        )

        set(ADDITIONAL_OBJECTS ${ADDITIONAL_OBJECTS} "${CMAKE_CURRENT_BINARY_DIR}/${output}.obj" PARENT_SCOPE)
    endfunction()

    binary_to_obj("opencl" "kernel.cl" "opencl_kernel")
else ()
    add_definitions(-DEMBEDDED_KERNEL=0)
endif ()

find_package(OpenCL REQUIRED)

add_executable(iphasher_opencl main.cpp opencl/kernel.cl ${ADDITIONAL_OBJECTS})

target_include_directories(iphasher_opencl PRIVATE ${OpenCL_INCLUDE_DIRS})
target_link_libraries(iphasher_opencl ${OpenCL_LIBRARIES})