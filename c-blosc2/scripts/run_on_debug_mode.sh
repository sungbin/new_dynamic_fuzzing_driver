#!/bin/bash
# ./run_on_debug_mode.sh ./BYTE_FILE ./OUT_FILE

if [ ! -f new_fuzzing_driver_debug ] ; then

clang++-12 \
        new_fuzzing_driver.cc \
	-DDEBUG \
        ./blosc/libblosc2.a \
        -I../include \
        -fsanitize=fuzzer,address \
        -fprofile-instr-generate -fcoverage-mapping \
        -o new_fuzzing_driver_debug -g -O0

fi

ASAN_OPTIONS=detect_leaks=0 ./new_fuzzing_driver_debug $1 -detect_leaks=0  > $2
