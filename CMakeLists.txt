cmake_minimum_required(VERSION 3.21)
project(kellect)

include_directories(SYSTEM ${KERNEL_INCLUDE_DIRS})

set(CMAKE_CXX_STANDARD 14)

add_executable(kellect src/main.cpp src/bpf_program.c src/trace/test/execsnoop.h src/trace/test/execsnoop.bpf.c src/include/minimal.h)
