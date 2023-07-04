#!/bin/bash

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

if [ $# -eq 0 ] ; then
  echo "./debug.sh TEST_BYTES"
  exit
fi

INPUT_BYTES=$1
if [ -f input.bin ] ; then
  rm input.bin
fi
python3 bytes_writer.py "${INPUT_BYTES}"
#python3 bytes_writer.py "6 0 0 2 0 4 0 1"

ASAN_OPTIONS=detect_leaks=0 ./new_fuzzing_driver_debug input.bin -detect_leaks=0
