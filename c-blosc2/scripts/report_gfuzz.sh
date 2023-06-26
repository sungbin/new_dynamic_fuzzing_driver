#!/bin/bash

llvm-cov report ./new_fuzzing_driver -instr-profile=merged.profdata -ignore-filename-regex="(fuzz_compress_frame)|(\\.h)|(internal-complibs)|(tests)|(plugins)|(\.cc)"
