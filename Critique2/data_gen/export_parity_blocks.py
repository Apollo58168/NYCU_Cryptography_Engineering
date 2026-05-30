import os

# ----------------------------
# Parameters
# ----------------------------
INPUT_FILE = "test_128mb.bin"
OUTPUT_FILE = "parity_blocks.bin"

NUM_BLOCKS = 128
BLOCK_SIZE = 1024 * 1024   # 1MB
TOTAL_SIZE = NUM_BLOCKS * BLOCK_SIZE

# 128 blocks -> 64 parity blocks
NUM_PARITY_BLOCKS = NUM_BLOCKS // 2

# ----------------------------
# Read binary file
# ----------------------------
def read_binary_file(filename):
    with open(filename, "rb") as f:
        return f.read()

# ----------------------------
# Split into 128 blocks
# ----------------------------
def split_into_blocks(data):
    if len(data) != TOTAL_SIZE:
        raise ValueError(
            f"File size mismatch: expected {TOTAL_SIZE} bytes, got {len(data)} bytes"
        )

    blocks = []
    for i in range(NUM_BLOCKS):
        start = i * BLOCK_SIZE
        end = start + BLOCK_SIZE
        blocks.append(data[start:end])
    return blocks

# ----------------------------
# XOR two blocks
# ----------------------------
def xor_blocks(block_a, block_b):
    return bytes(a ^ b for a, b in zip(block_a, block_b))

# ----------------------------
# Build parity blocks
# P0 = D0 XOR D1
# P1 = D2 XOR D3
# ...
# P63 = D126 XOR D127
# ----------------------------
def build_parity_blocks(blocks):
    parity_blocks = []

    for i in range(0, NUM_BLOCKS, 2):
        parity = xor_blocks(blocks[i], blocks[i + 1])
        parity_blocks.append(parity)

    return parity_blocks

# ----------------------------
# Write parity blocks to .bin
# ----------------------------
def write_parity_blocks(filename, parity_blocks):
    with open(filename, "wb") as f:
        for block in parity_blocks:
            f.write(block)

# ----------------------------
# Main
# ----------------------------
def main():
    if not os.path.exists(INPUT_FILE):
        print(f"Error: '{INPUT_FILE}' not found.")
        return

    data = read_binary_file(INPUT_FILE)
    blocks = split_into_blocks(data)
    parity_blocks = build_parity_blocks(blocks)
    write_parity_blocks(OUTPUT_FILE, parity_blocks)

    print("Parity blocks exported successfully.")
    print(f"Output file: {OUTPUT_FILE}")
    print(f"Number of parity blocks: {len(parity_blocks)}")
    print(f"Each parity block size: {BLOCK_SIZE} bytes")
    print(f"Total output size: {len(parity_blocks) * BLOCK_SIZE} bytes")

if __name__ == "__main__":
    main()