# Project 2: Critique & Implementation 2

Course: Cryptography Engineering  
Spec date: April 16, 2026  
Deadline: May 15, 2026, 23:59 Taiwan Time

Critique2/
├── data_gen/
│   ├── export_parity_blocks.py
│   ├── export_trusted_merkle_tree.py
│   ├── generate_1mb.py
│   ├── generate_128mb.py
│   └── generate_corrupted.py
├── .gitignore
├── Critique2.pdf
├── project2_spec.pdf
├── README.md
├── task1.py
├── task2.py
├── task3.py
└── task4.py

本作業分成兩個主要部分：

1. Critique: 閱讀 Merkle digital signature paper 並撰寫英文評論。
2. Implementation: 實作 Dynamic Merkle Tree 系統，用於偵測、定位、更新與修復資料區塊。

## 目標

傳統 single hash 對大型檔案或大型狀態資料庫不夠有效率。只要資料中一小部分改變，就必須重新 hash 整份資料，也無法直接定位錯誤位置。

本 project 要實作一個以 Merkle Tree 為核心的系統，處理 128MB 檔案，並將其切成 `2^7 = 128` 個 block，每個 block 為 1MB。

Merkle Tree 要支援：

- Detecting: 判斷資料是否被修改。
- Localizing: 找出哪一個 block 被修改。
- Updating: 單一 block 更新後，只更新 leaf 到 root 的路徑。
- Correcting: 搭配 XOR parity blocks 修復 corrupted block。

## 測試資料產生

Spec 要求使用提供的程式產生輸入資料，確保格式一致。

| Script | Output | 用途 |
| --- | --- | --- |
| `generate_128mb.py` | `test_128mb.bin` | 產生 128MB 原始資料，所有 task 的主要輸入 |
| `generate_corrupted.py` | `test_128mb_corrupted.bin` | 從原始資料 flip one bit，產生 corrupted file |
| `generate_1mb.py` | `test_1mb.bin` | 產生 1MB replacement block，給 Task 3 使用 |
| `export_trusted_merkle_tree.py` | `trusted_merkle_tree.bin` | 從正確原始資料產生 trusted Merkle Tree |
| `export_parity_blocks.py` | `parity_blocks.bin` | 從正確原始資料產生 XOR parity blocks，給 Task 4 使用 |

建議執行順序：

```bash
python3 generate_128mb.py
python3 generate_1mb.py
python3 export_trusted_merkle_tree.py
python3 export_parity_blocks.py
python3 generate_corrupted.py
```

## Merkle Tree 格式

`trusted_merkle_tree.bin` 儲存完整 Merkle Tree，格式為由下而上依序寫入：

```text
level 0: 128 leaf hashes
level 1: 64 hashes
level 2: 32 hashes
level 3: 16 hashes
level 4: 8 hashes
level 5: 4 hashes
level 6: 2 hashes
level 7: 1 root hash
```

每個 hash 是 SHA-256 digest，大小為 32 bytes。

總 hash 數：

```text
128 + 64 + 32 + 16 + 8 + 4 + 2 + 1 = 255
```

總檔案大小：

```text
255 * 32 = 8160 bytes
```

## Task 1: Single Hash vs. Merkle Tree

### Objective

比較 single hash 的 all-or-nothing 方法與 Merkle Tree 結構。

### Scenario

將 128MB 檔案切成 `2^7 = 128` 個 blocks。

### Input

- `test_128mb.bin`

### 要完成的事

1. 對整份 128MB 檔案計算 single SHA-256 hash。
2. 對同一份檔案建立 Merkle Tree。
3. 比較兩種方法的初始建構時間。
4. 計算 Merkle Tree 內部節點的 memory overhead。

### Output

Single hash result:

- Whole-file SHA-256 hash。
- 計算 single hash 花費時間。

Merkle Tree result:

- Merkle root。
- 建立完整 Merkle Tree 花費時間。
- Internal node memory overhead。

## Task 2: Efficient Error Localization

### Objective

實作 top-down search algorithm，找出哪一個 data block 被破壞。

### Scenario

128 個 blocks 中，有一個 block 的一個 bit 被 flip。你要找出 corrupted block index。

### Input

- `test_128mb_corrupted.bin`
- `trusted_merkle_tree.bin`
- 不可使用原始乾淨資料 `test_128mb.bin`

### 要完成的事

1. 使用 corrupted file 重建一棵新的 Merkle Tree。
2. 讀取 `trusted_merkle_tree.bin`。
3. 實作 `locate_error()`。
4. 在 `locate_error()` 中記錄 hash comparison count。

### Top-down search 邏輯

從 root 往下找。每一層只需要比較目前節點的 left child：

- 如果 left child hash 不一致，錯誤在左子樹。
- 如果 left child hash 一致，在 single corrupted block 假設下，錯誤在右子樹。

因為有 128 個 blocks：

```text
H = log2(128) = 7
```

所以 comparison count 必須剛好是 7。

### Output

1. Trusted Merkle Tree root。
2. Corrupted file root。
3. Corrupted block index。
4. Comparison count。

## Task 3: Efficient Node Replacement

### Objective

當一個 block 被替換後，用 efficient path update 更新 Merkle root，並和 full tree reconstruction 比較效率。

### Scenario

使用者指定 `0 ~ 127` 的 block index，將該 block 替換成 `test_1mb.bin` 的內容。

### Input

- `test_128mb.bin`
- `test_1mb.bin`
- User input: block index, range `0 ~ 127`

### 要完成的事

1. 從 `test_128mb.bin` 建立原始 Merkle Tree。
2. 用 `test_1mb.bin` 替換其中一個 block。
3. 實作 `replace_node()`，只更新 affected path，也就是 leaf 到 root。
4. 用兩種方式計算 updated Merkle root：
   - Path update: `replace_node()`
   - Full tree reconstruction: 重新建立整棵 Merkle Tree
5. 測量並比較兩種方法的執行時間。

### 正確性檢查

`replace_node()` 得到的 updated root 必須和 full reconstruction 得到的 updated root 完全相同。

### Output

1. Original Merkle Tree root。
2. Updated Merkle root using `replace_node()`。
3. Updated Merkle root using full tree reconstruction。
4. Verification result: 兩個 updated roots 是否相同。
5. Execution time of `replace_node()`。
6. Execution time of full tree reconstruction。
7. Performance comparison，例如 speedup factor。

## Task 4: Advanced Self-Healing

### Objective

整合 Merkle Tree detection 和 XOR parity correction，定位並修復 corrupted block。

### Scenario

128 個 blocks 中，有一個 block 的一個 bit 被 flip。你只會拿到：

- corrupted data
- trusted Merkle Tree
- parity blocks

你必須找出 corrupted block，並恢復原始資料。

### Input

- `test_128mb_corrupted.bin`
- `trusted_merkle_tree.bin`
- `parity_blocks.bin`
- 不可使用原始乾淨資料 `test_128mb.bin`

### Parity block 格式

`parity_blocks.bin` 由原始正確資料產生：

```text
P0  = D0   XOR D1
P1  = D2   XOR D3
P2  = D4   XOR D5
...
P63 = D126 XOR D127
```

也就是每兩個 data blocks 對應一個 parity block。

如果 corrupted block index 是 `i`：

```text
parity_index = i // 2
sibling_index = i ^ 1
correct_block = parity_block[parity_index] XOR sibling_block
```

### 要完成的事

1. 用 `trusted_merkle_tree.bin` 和 corrupted file 定位 corrupted block。
2. 使用 `parity_blocks.bin` 和 sibling block reconstruct 正確 block。
3. 使用 `replace_node()` 修復 Merkle Tree。
4. 驗證 repaired Merkle root 是否等於 trusted root。

### Output

1. Trusted Merkle Tree root。
2. Corrupted file root。
3. Corrupted block index。
4. Comparison count from `locate_error()`。
5. Parity block index used for recovery。
6. Sibling block index。
7. Repaired Merkle root。
8. Verification result: repaired root 是否等於 trusted root。

## Implementation Report

Report 需要解釋你的實作邏輯，並整理實驗結果。

需要包含：

- Task 1 single hash 與 Merkle Tree 的建構時間。
- Task 1 Merkle Tree memory overhead。
- Task 2 為什麼 comparison count 是 `log2(n)`。
- Task 3 path update 與 full reconstruction 的時間比較。
- Task 4 如何用 parity 修復 block。
- 對結果的討論，例如時間、記憶體、proof size、效率提升。

Spec 要求完成下列表格，`n = 2^7` blocks：

| Operation | Single Hash | Merkle Tree | Improvement Factor |
| --- | --- | --- | --- |
| Detecting Error | Scans ? MB | ? | ? |
| Localizing Error | Impossible | ? comparisons | ? |
| Updating 1 Block | Computes ? MB | ? | ? |
| Proof Size (Bytes) | ? | ? | ? |

## Critique

閱讀論文：

```text
A digital signature based on a conventional encryption function
by Ralph C. Merkle
```

要求：

- English text-only。
- 約 1000-1200 words。
- 可以使用 ChatGPT、Gemini 或其他 AI 工具輔助，但要說明哪個答案比較合理。
- 需要提出一個 technical specification、mechanism 或 algorithm，用來 mitigate paper 中的問題。

建議回答：

- Paper name。
- Summary。
- What problem is the paper trying to solve?
- Why does the problem matter?
- What approach is used?
- What conclusion is drawn?
- Strengths。
- Weaknesses。
- Your reflection。
- What did you learn?
- How would you improve or extend the work?
- What unresolved questions do you want to investigate?
- Broader impacts。

## Grading

Critique:

- 佔 final score 10%。
- 滿分 100。

Implementation:

- 佔 final score 5%。
- 滿分 100。

Implementation 配分：

| Item | Points |
| --- | --- |
| Task 1 | 20 |
| Task 2 | 20 |
| Task 3 | 20 |
| Task 4 | 20 |
| Report | 20 |

Late submission:

- 每晚一天扣 final score 0.5 分。
- 最多扣 20 天。
- 超過 20 天以 0 分計算。

## Submission

上傳一個 zip file，內容包含：

```text
<group number>_project2/
  task1.py
  task2.py
  task3.py
  task4.py
  <group number>_critique.pdf
  <group number>_report.pdf
```

## 常用執行指令

```bash
cd /home/apollo/Crypto_Engineering/NYCU_Cryptography_Engineering/project2

python3 generate_128mb.py
python3 generate_1mb.py
python3 export_trusted_merkle_tree.py
python3 export_parity_blocks.py
python3 generate_corrupted.py

python3 task3.py
```
