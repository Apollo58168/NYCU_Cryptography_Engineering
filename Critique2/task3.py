import hashlib
import os
import time


# --- Parameters ---
NUM_BLOCKS = 128
BLOCK_SIZE = 1024 * 1024
TOTAL_SIZE = NUM_BLOCKS * BLOCK_SIZE

INPUT_FILE = "test_128mb.bin"
REPLACEMENT_FILE = "test_1mb.bin"


def sha256(data):
    return hashlib.sha256(data).digest()


def read_binary_file(filename):
    with open(filename, "rb") as f:
        return f.read()


def split_into_blocks(data):
    if len(data) != TOTAL_SIZE:
        raise ValueError(
            f"File size mismatch: expected {TOTAL_SIZE} bytes, got {len(data)} bytes"
        )

    blocks = []
    for i in range(NUM_BLOCKS):
        start = i * BLOCK_SIZE
        blocks.append(data[start : start + BLOCK_SIZE])
    return blocks


def build_merkle_tree(blocks):
    if len(blocks) != NUM_BLOCKS:
        raise ValueError(f"Expected {NUM_BLOCKS} blocks, got {len(blocks)}")

    tree = []
    current_level = [sha256(block) for block in blocks]
    tree.append(current_level)

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            next_level.append(sha256(current_level[i] + current_level[i + 1]))
        tree.append(next_level)
        current_level = next_level

    return tree


def replace_node(tree, block_index, new_block):
    if not 0 <= block_index < NUM_BLOCKS:
        raise ValueError(f"Block index must be between 0 and {NUM_BLOCKS - 1}")
    if len(new_block) != BLOCK_SIZE:
        raise ValueError(
            f"Replacement block size mismatch: expected {BLOCK_SIZE} bytes, got {len(new_block)} bytes"
        )

    updated_tree = [level[:] for level in tree]
    current_idx = block_index

    updated_tree[0][current_idx] = sha256(new_block)

    for level in range(len(updated_tree) - 1):
        parent_idx = current_idx // 2
        sibling_idx = current_idx ^ 1

        if current_idx % 2 == 0:
            left_hash = updated_tree[level][current_idx]
            right_hash = updated_tree[level][sibling_idx]
        else:
            left_hash = updated_tree[level][sibling_idx]
            right_hash = updated_tree[level][current_idx]

        updated_tree[level + 1][parent_idx] = sha256(left_hash + right_hash)
        current_idx = parent_idx

    return updated_tree


def ask_block_index():
    while True:
        try:
            block_index = int(input(f"Enter block index to replace (0 ~ {NUM_BLOCKS - 1}): "))
        except ValueError:
            print("Invalid input. Please enter an integer.")
            continue

        if 0 <= block_index < NUM_BLOCKS:
            return block_index

        print("Out of range.")


def main():
    if not os.path.exists(INPUT_FILE):
        print(f"Error: '{INPUT_FILE}' not found.")
        return
    if not os.path.exists(REPLACEMENT_FILE):
        print(f"Error: '{REPLACEMENT_FILE}' not found.")
        return

    original_data = read_binary_file(INPUT_FILE)
    replacement_block = read_binary_file(REPLACEMENT_FILE)

    if len(replacement_block) != BLOCK_SIZE:
        print(
            f"Error: '{REPLACEMENT_FILE}' must be exactly {BLOCK_SIZE} bytes, got {len(replacement_block)} bytes."
        )
        return

    blocks = split_into_blocks(original_data)
    original_tree = build_merkle_tree(blocks)
    original_root = original_tree[-1][0]

    block_index = ask_block_index()

    start = time.perf_counter()
    updated_tree_by_path = replace_node(original_tree, block_index, replacement_block)
    path_update_time = time.perf_counter() - start
    path_update_root = updated_tree_by_path[-1][0]

    updated_blocks = blocks[:]
    updated_blocks[block_index] = replacement_block

    start = time.perf_counter()
    updated_tree_by_full_rebuild = build_merkle_tree(updated_blocks)
    full_rebuild_time = time.perf_counter() - start
    full_rebuild_root = updated_tree_by_full_rebuild[-1][0]

    roots_match = path_update_root == full_rebuild_root
    speedup = full_rebuild_time / path_update_time if path_update_time > 0 else float("inf")

    print(f"1. Original Merkle Tree Root:                 {original_root.hex()}")
    print(f"2. Updated Root using replace_node():         {path_update_root.hex()}")
    print(f"3. Updated Root using full reconstruction:    {full_rebuild_root.hex()}")
    print(f"4. Verification Result:                       {roots_match}")
    print(f"5. Execution Time of replace_node():          {path_update_time:.9f} seconds")
    print(f"6. Execution Time of full reconstruction:     {full_rebuild_time:.9f} seconds")
    print(f"7. Performance Comparison:                    {speedup:.2f}x faster")


if __name__ == "__main__":
    main()
