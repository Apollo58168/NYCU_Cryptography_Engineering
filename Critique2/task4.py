import hashlib
import os

# --- Parameters ---
NUM_BLOCKS = 128
BLOCK_SIZE = 1024 * 1024
HASH_SIZE = 32

TRUSTED_TREE_FILE = "trusted_merkle_tree.bin"
CORRUPTED_DATA_FILE = "test_128mb_corrupted.bin"
PARITY_BLOCKS_FILE = "parity_blocks.bin"


def sha256(data):
    return hashlib.sha256(data).digest()

def read_binary_file(filename):
    with open(filename, "rb") as f:
        return f.read()

def split_into_blocks(data, expected_blocks):
    if len(data) != expected_blocks * BLOCK_SIZE:
        raise ValueError(f"Size mismatch: expected {expected_blocks * BLOCK_SIZE} bytes.")
    blocks = []
    for i in range(expected_blocks):
        start = i * BLOCK_SIZE
        blocks.append(data[start : start + BLOCK_SIZE])
    return blocks

# --- From Task 2 ---
def load_trusted_tree(filename):
    with open(filename, "rb") as f:
        data = f.read()
    
    tree = []
    offset = 0
    current_level_size = NUM_BLOCKS
    
    while current_level_size >= 1:
        level_hashes = []
        for _ in range(current_level_size):
            level_hashes.append(data[offset : offset + HASH_SIZE])
            offset += HASH_SIZE
        tree.append(level_hashes)
        current_level_size //= 2
    return tree

def locate_error(trusted_tree, corrupted_tree):
    comparison_count = 0
    current_idx = 0 
    
    for level in range(6, -1, -1):
        comparison_count += 1
        left_child_idx = current_idx * 2
        
        if corrupted_tree[level][left_child_idx] != trusted_tree[level][left_child_idx]:
            current_idx = left_child_idx
        else:
            current_idx = left_child_idx + 1
            
    return current_idx, comparison_count

# --- From Task 3 ---
def build_merkle_tree(blocks):
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

# --- New Function for Task 4 ---
def xor_blocks(block1, block2):
    """XORs two 1MB byte blocks efficiently."""
    int1 = int.from_bytes(block1, 'big')
    int2 = int.from_bytes(block2, 'big')
    return (int1 ^ int2).to_bytes(BLOCK_SIZE, 'big')


def main():
    if not all(os.path.exists(f) for f in [TRUSTED_TREE_FILE, CORRUPTED_DATA_FILE, PARITY_BLOCKS_FILE]):
        print("Error: Missing necessary .bin files!")
        return

    # 1. Read files
    trusted_tree = load_trusted_tree(TRUSTED_TREE_FILE)
    corrupted_data = read_binary_file(CORRUPTED_DATA_FILE)
    parity_data = read_binary_file(PARITY_BLOCKS_FILE)

    # 2. Split into blocks
    corrupted_blocks = split_into_blocks(corrupted_data, NUM_BLOCKS)
    parity_blocks = split_into_blocks(parity_data, NUM_BLOCKS // 2)

    # 3. Build corrupted tree & Locate the error (The Detective)
    corrupted_tree = build_merkle_tree(corrupted_blocks)
    bad_block_index, count = locate_error(trusted_tree, corrupted_tree)

    # 4. Calculate Parity and Sibling Indices
    parity_block_index = bad_block_index // 2
    sibling_block_index = bad_block_index ^ 1

    # 5. Recover data using XOR (The Correction)
    sibling_block = corrupted_blocks[sibling_block_index]
    parity_block = parity_blocks[parity_block_index]
    recovered_block = xor_blocks(sibling_block, parity_block)

    # 6. Repair the Merkle Tree (The Update)
    repaired_tree = replace_node(corrupted_tree, bad_block_index, recovered_block)
    
    # 7. Verification
    trusted_root = trusted_tree[-1][0]
    corrupted_root = corrupted_tree[-1][0]
    repaired_root = repaired_tree[-1][0]
    is_verified = (repaired_root == trusted_root)

    # 8. Formatting output
    print(f"1. Trusted Merkle Tree root:             {trusted_root.hex()}")
    print(f"2. Corrupted file root:                  {corrupted_root.hex()}")
    print(f"3. Corrupted block index:                {bad_block_index}")
    print(f"4. Comparison count:                     {count}")
    print(f"5. Parity block index used for recovery: {parity_block_index}")
    print(f"6. Sibling block index:                  {sibling_block_index}")
    print(f"7. Repaired Merkle Root:                 {repaired_root.hex()}")
    print(f"8. Verification result:                  {is_verified}")


if __name__ == "__main__":
    main()