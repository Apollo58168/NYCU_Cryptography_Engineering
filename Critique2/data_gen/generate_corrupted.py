# make_corrupted_file.py

import os

# ----------------------------
# Parameters
# ----------------------------
INPUT_FILE = "test_128mb.bin"
OUTPUT_FILE = "test_128mb_corrupted.bin"

NUM_BLOCKS = 128
BLOCK_SIZE = 1024 * 1024                  # 1MB
BITS_PER_BLOCK = BLOCK_SIZE * 8
TOTAL_SIZE = NUM_BLOCKS * BLOCK_SIZE

# ----------------------------
# Read file
# ----------------------------
def read_binary_file(filename):
    with open(filename, "rb") as f:
        return bytearray(f.read())   # bytearray 才能改 bit

# ----------------------------
# Write file
# ----------------------------
def write_binary_file(filename, data):
    with open(filename, "wb") as f:
        f.write(data)

# ----------------------------
# Flip one bit
# block_index: 0 ~ 127
# bit_index_in_block: 0 ~ BLOCK_SIZE*8-1
# ----------------------------
def flip_bit(data, block_index, bit_index_in_block):
    byte_index_in_block = bit_index_in_block // 8
    bit_index_in_byte = bit_index_in_block % 8

    global_byte_index = block_index * BLOCK_SIZE + byte_index_in_block

    # bit 0 視為該 byte 的最高位元
    mask = 1 << (7 - bit_index_in_byte)

    data[global_byte_index] ^= mask

# ----------------------------
# Main
# ----------------------------
def main():
    if not os.path.exists(INPUT_FILE):
        print(f"Error: '{INPUT_FILE}' not found.")
        return

    data = read_binary_file(INPUT_FILE)

    if len(data) != TOTAL_SIZE:
        print(f"Error: file size mismatch. Expected {TOTAL_SIZE} bytes, got {len(data)} bytes.")
        return

    print(f"Input file: {INPUT_FILE}")
    print(f"Output file: {OUTPUT_FILE}")
    print(f"Block index range: 0 ~ {NUM_BLOCKS - 1}")
    print(f"Bit index range inside one block: 0 ~ {BITS_PER_BLOCK - 1}")
    print()

    # user input: block index
    while True:
        try:
            block_index = int(input(f"Enter block index to modify (0 ~ {NUM_BLOCKS - 1}): "))
            if 0 <= block_index < NUM_BLOCKS:
                break
            else:
                print("Out of range.")
        except ValueError:
            print("Invalid input. Please enter an integer.")

    # user input: bit index in block
    while True:
        try:
            bit_index_in_block = int(input(f"Enter bit index inside block (0 ~ {BITS_PER_BLOCK - 1}): "))
            if 0 <= bit_index_in_block < BITS_PER_BLOCK:
                break
            else:
                print("Out of range.")
        except ValueError:
            print("Invalid input. Please enter an integer.")

    # flip bit
    flip_bit(data, block_index, bit_index_in_block)

    # save corrupted file
    write_binary_file(OUTPUT_FILE, data)

    print("\nDone.")
    print(f"Modified block index: {block_index}")
    print(f"Modified bit index in block: {bit_index_in_block}")
    print(f"Corrupted file saved as: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()