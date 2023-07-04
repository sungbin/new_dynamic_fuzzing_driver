#!/bin/python3

import sys
import json
from parse import parse

assert len(sys.argv) == 2, "./exported_code_to_line_cov.py CODE_WITH_COVERAGE_PATH"

with open(sys.argv[1]) as f:
    lines = [line.rstrip() for line in f]

out_json = {}
target_src = ''
line_lst = []

for line in lines:
    if line.isspace():
        continue
    if '/new_fuzzing_driver/' in line:
        if target_src != '':
            out_json[target_src] = line_lst
            line_lst = []
        target_src = line[:-1]
        continue
    line = line.replace(' ','')
    pos1 = line.find('|')
    if pos1 == -1:
        continue
    line_num = int(line[:pos1])

    pos2 = line[pos1+1:].find('|') + pos1+1
    hit_cnt = line[pos1+1:pos2]

    if hit_cnt == '':
        continue
    elif 'k' in hit_cnt or 'M' in hit_cnt or 'E' in hit_cnt:
        line_lst.append(line_num)
        continue
    elif int(hit_cnt) < 1:
        continue

    line_lst.append(line_num)

if target_src != '':
    out_json[target_src] = line_lst

print(json.dumps(out_json))
