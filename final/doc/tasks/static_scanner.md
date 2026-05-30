# static_scanner.py 任務

## 目標

對 Python source files 執行快速靜態掃描，找出可能的 cryptographic API usage 與演算法關鍵字，輸出 `StaticMatch`。

## 輸入依據

- `doc/final_project_proposal.md`
- `doc/detailed-design.md`

## 輸出

- `src/pqc_audit/static_scanner.py`
- `tests/test_static_scanner.py`

## 最小可執行任務

- [ ] 建立 `StaticScanner` 類別
- [ ] 實作 `scan(source_files)` 介面
- [ ] 偵測 `from cryptography.hazmat.primitives.asymmetric import rsa`
- [ ] 偵測 `from cryptography.hazmat.primitives.asymmetric import ec`
- [ ] 偵測 `from cryptography.hazmat.primitives.asymmetric import dh`
- [ ] 偵測 `rsa.generate_private_key(...)`
- [ ] 偵測 `ec.generate_private_key(...)`
- [ ] 偵測 `dh.generate_parameters(...)`
- [ ] 偵測 `ssl.SSLContext(...)`
- [ ] 偵測 `ssl.create_default_context(...)`
- [ ] 偵測 `Crypto.PublicKey.RSA`
- [ ] 偵測 `Cryptodome.PublicKey.RSA`
- [ ] 偵測字串或程式碼中的 `RSA`
- [ ] 偵測字串或程式碼中的 `ECC`
- [ ] 偵測字串或程式碼中的 `ECDSA`
- [ ] 偵測字串或程式碼中的 `ECDH`
- [ ] 偵測字串或程式碼中的 `Diffie-Hellman`
- [ ] 偵測字串或程式碼中的 `DH`
- [ ] 為每筆 match 填入 `rule_id`
- [ ] 為每筆 match 填入 `algorithm_hint`
- [ ] 為每筆 match 填入 `library_hint`
- [ ] 為每筆 match 填入 `line_number`
- [ ] 為每筆 match 填入 `line_text`
- [ ] 實作 Python AST 分析可用時優先使用
- [ ] 實作 syntax error 時 regex fallback
- [ ] 撰寫測試覆蓋 RSA rule
- [ ] 撰寫測試覆蓋 EC/ECC rule
- [ ] 撰寫測試覆蓋 DH rule
- [ ] 撰寫測試覆蓋 SSL rule
- [ ] 撰寫測試覆蓋 PyCryptodome RSA rule
- [ ] 撰寫測試確認 comment 或 string 仍會成為 candidate
- [ ] 撰寫測試確認 syntax error 不會讓 scanner 崩潰
- [ ] 撰寫測試確認 unrelated code 不產生 match
- [ ] 執行 `uv run pytest tests/test_static_scanner.py`

## 驗收條件

- [ ] 靜態掃描只輸出 `StaticMatch`
- [ ] scanner 不呼叫 Gemini
- [ ] scanner 不產生風險分數
- [ ] 測試不需要網路
- [ ] `uv run pytest tests/test_static_scanner.py` 通過

## 不做的事

- [ ] 不判斷是否真正 security-sensitive
- [ ] 不產生 `CryptoEvidence`
- [ ] 不產生 PQC 建議
