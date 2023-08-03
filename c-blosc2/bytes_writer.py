#!/usr/bin/python3
# Input: (Value)
#    ex: "2 2 2" -> 1-byte(2), 1-byte(2), 1-byte(2)
# Output: input.bin

import sys

def write_bytes_to_file(values, output_file):
    bytes_data = bytes([int(value) for value in values])
    bytes_data = bytes_data[::-1]
    with open(output_file, 'wb') as f:
        f.write(bytes_data)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python bytes_writer.py <values> <out-path>")
        sys.exit(1)

    values = sys.argv[1].split()
    #output_file = "input.bin"
    output_file = sys.argv[2]

    write_bytes_to_file(values, output_file)
    print(f"Bytes written to {output_file}")
