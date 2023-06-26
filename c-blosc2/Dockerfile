FROM ubuntu:20.04
ENV TERM xterm-256color
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install \
    clang-12 make cmake git wget curl tar gdb vim clang-tools-12 \
    python3 python3-pip libprotobuf-dev protobuf-compiler

WORKDIR /new_fuzzing_driver

# Copy submodule directory
COPY submodules/c-blosc2 /new_fuzzing_driver/c-blosc2

# Build static library
RUN mkdir /new_fuzzing_driver/c-blosc2/build && \
    cd /new_fuzzing_driver/c-blosc2/build && \
    cmake .. && \
    cmake --build .

# Build Instrumented library
ENV CC="/usr/bin/clang-12" CXX="/usr/bin/clang++-12" \
    CFLAGS="-fprofile-instr-generate -fcoverage-mapping"

WORKDIR /new_fuzzing_driver/c-blosc2
RUN mkdir build_cov && \
    cd build_cov && \
    LINE_ADDED='set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -fprofile-instr-generate -fcoverage-mapping")' && \
    sed -i'' -r -e '/project\(blosc LANGUAGES C ASM\)/a\set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -fprofile-instr-generate -fcoverage-mapping")' ../CMakeLists.txt && \
    cmake .. && \
    cmake --build .

RUN unset CC CXX CFLAGS

WORKDIR /new_fuzzing_driver/c-blosc2/build
COPY c-blosc2/new_fuzzing_driver.cc /new_fuzzing_driver/c-blosc2/build/new_fuzzing_driver.cc

# Build fuzzing driver with static library
RUN clang++-12 \
    new_fuzzing_driver.cc \
    ./blosc/libblosc2.a \
    -I../include \
    -fsanitize=fuzzer,address \
    -o new_fuzzing_driver -g -O0

# Build fuzzing driver with Instrumented library
RUN cd ../build_cov && \
    cp ../build/new_fuzzing_driver.cc ./new_fuzzing_driver.cc && \ 
    clang++-12 \
        new_fuzzing_driver.cc \
        ./blosc/libblosc2.a \
        -I../include \
        -fsanitize=fuzzer,address \
        -fprofile-instr-generate -fcoverage-mapping \
        -o new_fuzzing_driver -g -O0

COPY c-blosc2/scripts/run_on_debug_mode.sh /new_fuzzing_driver/c-blosc2/build/run_on_debug_mode.sh 
