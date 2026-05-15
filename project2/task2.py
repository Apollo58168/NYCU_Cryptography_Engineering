import hashlib
import os

# --- 參數設定 (與 Template 一致) ---
NUM_BLOCKS = 128
BLOCK_SIZE = 1024 * 1024
HASH_SIZE = 32
TRUSTED_TREE_FILE = "trusted_merkle_tree.bin"
CORRUPTED_DATA_FILE = "test_128mb_corrupted.bin"

def sha256(data):
    return hashlib.sha256(data).digest()

# 1. 讀取 Trusted Tree 並還原層次結構
def load_trusted_tree(filename):
    with open(filename, "rb") as f:
        data = f.read()
    
    tree = []
    offset = 0
    current_level_size = NUM_BLOCKS
    
    # 按照 128, 64, 32, 16, 8, 4, 2, 1 的順序切分
    while current_level_size >= 1:
        level_hashes = []
        for _ in range(current_level_size):
            level_hashes.append(data[offset : offset + HASH_SIZE])
            offset += HASH_SIZE
        tree.append(level_hashes)
        current_level_size //= 2
    return tree

# 2. 拿損壞的檔案建立新的 Merkle Tree (參考 Template 邏輯)
def build_corrupted_tree(filename):
    with open(filename, "rb") as f:
        data = f.read()
    
    blocks = [data[i*BLOCK_SIZE : (i+1)*BLOCK_SIZE] for i in range(NUM_BLOCKS)]
    
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

# 3. 核心偵探函數：Top-down Search
def locate_error(trusted_tree, corrupted_tree):
    comparison_count = 0
    current_idx = 0  # 從 Root 的索引開始
    
    # 從最頂層 (Root) 的下一層開始往下找
    # 樹的高度 H = 7 (不含 leaf 共有 7 次分支判定)
    # level 7 是 root, 我們從 level 6 判斷起
    for level in range(6, -1, -1):
        comparison_count += 1
        
        # 取得當前路徑下，左子節點的 index
        # 在 Merkle Tree 中，父節點 i 的左子節點是 2*i
        left_child_idx = current_idx * 2
        
        # 關鍵比較：比對左子節點是否一致
        if corrupted_tree[level][left_child_idx] != trusted_tree[level][left_child_idx]:
            # 如果左邊不一致，錯誤在左半邊
            current_idx = left_child_idx
        else:
            # 如果左邊一致，錯誤一定在右半邊
            current_idx = left_child_idx + 1
            
    return current_idx, comparison_count

def main():
    # 檢查檔案是否存在
    if not os.path.exists(TRUSTED_TREE_FILE) or not os.path.exists(CORRUPTED_DATA_FILE):
        print("錯誤：找不到必要的 .bin 檔案！")
        return

    # 載入兩棵樹
    trusted_tree = load_trusted_tree(TRUSTED_TREE_FILE)
    corrupted_tree = build_corrupted_tree(CORRUPTED_DATA_FILE)

    # 執行搜尋
    bad_block_index, count = locate_error(trusted_tree, corrupted_tree)

    # 輸出結果
    print(f"1. Trusted Merkle Tree Root:  {trusted_tree[-1][0].hex()}")
    print(f"2. Corrupted File Root:       {corrupted_tree[-1][0].hex()}")
    print(f"3. Corrupted Block Index:     {bad_block_index}")
    print(f"4. Comparison Count:          {count}")

    # 驗證約束
    # if count == 7:
    #     print("\n[驗證成功] 比對次數剛好為 log2(128) = 7 次。")

if __name__ == "__main__":
    main()