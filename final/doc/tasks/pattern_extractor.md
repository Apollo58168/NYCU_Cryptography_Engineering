# pattern_extractor.py 任務

## 目標

將 `StaticMatch` 轉換成結構化 `CryptoEvidence`，包含 snippet、行號、algorithm、library 與 usage type。

## 輸入依據

- `doc/final_project_proposal.md`
- `doc/detailed-design.md`

## 輸出

- `src/pqc_audit/pattern_extractor.py`
- `tests/test_pattern_extractor.py`

## 最小可執行任務

- [ ] 建立 `PatternExtractor` 類別
- [ ] 實作 `extract(source_files, matches)` 介面
- [ ] 依照 file path 找到對應 `SourceFile`
- [ ] 根據 match line number 萃取 snippet
- [ ] 實作 snippet 最大行數限制
- [ ] 實作 snippet start line
- [ ] 實作 snippet end line
- [ ] 合併同一檔案中相近的 matches
- [ ] 相距超過 snippet 限制時拆成不同 evidence
- [ ] 產生穩定 `evidence_id`
- [ ] 從 `algorithm_hint` 推測 `algorithm`
- [ ] 多個演算法 hint 同時存在時依設計中的高風險順序選擇
- [ ] 從 `library_hint` 推測 `library`
- [ ] 從 `generate_private_key` 推測 `key_generation`
- [ ] 從 `sign` 或 `verify` 推測 `signature`
- [ ] 從 `exchange` 或 `ECDH` 推測 `key_exchange`
- [ ] 從 `SSLContext` 或 `create_default_context` 推測 `tls_configuration`
- [ ] 無法推測時設定 `usage_type=unknown`
- [ ] 保留原始 `static_matches`
- [ ] 撰寫測試確認 snippet 邊界
- [ ] 撰寫測試確認相近 matches 會合併
- [ ] 撰寫測試確認相距過遠 matches 會拆分
- [ ] 撰寫測試確認 `evidence_id` 穩定
- [ ] 撰寫測試確認 algorithm 推測
- [ ] 撰寫測試確認 usage type 推測
- [ ] 執行 `uv run pytest tests/test_pattern_extractor.py`

## 驗收條件

- [ ] 輸出只使用 `CryptoEvidence`
- [ ] snippet 不超過設定限制
- [ ] evidence 保留原始檔案與行號
- [ ] 測試不需要 Gemini API 或網路
- [ ] `uv run pytest tests/test_pattern_extractor.py` 通過

## 不做的事

- [ ] 不呼叫 Gemini
- [ ] 不評估量子風險
- [ ] 不產生報告
