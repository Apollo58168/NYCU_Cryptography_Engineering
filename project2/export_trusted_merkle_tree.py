# export_trusted_merkle_tree.py

import hashlib
import os

# ----------------------------
# Parameters
# ----------------------------
INPUT_FILE = "test_128mb.bin"
OUTPUT_FILE = "trusted_merkle_tree.bin"

NUM_BLOCKS = 128
BLOCK_SIZE = 1024 * 1024   # 1MB
TOTAL_SIZE = NUM_BLOCKS * BLOCK_SIZE
HASH_SIZE = 32             # SHA-256 digest size

# ----------------------------
# SHA-256 helper
# ----------------------------
def sha256(data):
    return hashlib.sha256(data).digest()

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
# Build Merkle Tree
# tree[0] = leaf hashes
# tree[-1][0] = root
# ----------------------------
def build_merkle_tree(blocks):
    tree = []

    current_level = [sha256(block) for block in blocks]
    tree.append(current_level)

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            parent_hash = sha256(current_level[i] + current_level[i + 1])
            next_level.append(parent_hash)
        tree.append(next_level)
        current_level = next_level

    return tree

# ----------------------------
# Write tree to .bin
# format:
# level 0 hashes + level 1 hashes + ... + root hash
# each hash = 32 bytes
# ----------------------------
def write_tree_to_bin(filename, tree):
    with open(filename, "wb") as f:
        for level in tree:
            for node_hash in level:
                f.write(node_hash)

# ----------------------------
# Main
# ----------------------------
def main():
    if not os.path.exists(INPUT_FILE):
        print(f"Error: '{INPUT_FILE}' not found.")
        return

    data = read_binary_file(INPUT_FILE)
    blocks = split_into_blocks(data)

    tree = build_merkle_tree(blocks)
    root = tree[-1][0]

    write_tree_to_bin(OUTPUT_FILE, tree)

    total_hashes = sum(len(level) for level in tree)
    expected_bytes = total_hashes * HASH_SIZE

    print("Trusted Merkle Tree exported successfully.")
    print(f"Output file: {OUTPUT_FILE}")
    print(f"Merkle root: {root.hex()}")
    print(f"Total hashes stored: {total_hashes}")
    print(f"Output size: {expected_bytes} bytes")

if __name__ == "__main__":
    main()