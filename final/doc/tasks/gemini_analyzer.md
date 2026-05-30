# gemini_analyzer.py 任務

## 目標

將 `CryptoEvidence` 傳給 Gemini API 做語意分析，解析結構化 JSON，輸出 `SemanticAnalysis`。

## 輸入依據

- `doc/final_project_proposal.md`
- `doc/detailed-design.md`

## 輸出

- `src/pqc_audit/gemini_analyzer.py`
- `tests/test_gemini_analyzer.py`

## 最小可執行任務

- [ ] 建立 `SemanticAnalyzer` 類別
- [ ] 實作 `analyze(evidence_items)` 介面
- [ ] 建立 Gemini client 初始化邏輯
- [ ] 從 config 使用 Gemini API key
- [ ] 從 config 使用 Gemini model
- [ ] 實作單一 evidence 對應單一 API request
- [ ] 建立固定 prompt template
- [ ] prompt 包含 `evidence_id`
- [ ] prompt 包含 `file_path`
- [ ] prompt 包含 `start_line` 與 `end_line`
- [ ] prompt 包含 static algorithm hint
- [ ] prompt 包含 code snippet
- [ ] 要求 Gemini 只回傳 JSON
- [ ] 解析 `is_real_crypto_usage`
- [ ] 解析 `is_security_sensitive`
- [ ] 解析 `algorithm`
- [ ] 解析 `usage_type`
- [ ] 解析 `is_test_or_example`
- [ ] 解析 `explanation`
- [ ] 解析 `confidence`
- [ ] 保留 `raw_model_output`
- [ ] 驗證必要欄位存在
- [ ] Gemini API 失敗時產生低信心 fallback `SemanticAnalysis`
- [ ] Gemini 回傳 malformed JSON 時產生低信心 fallback `SemanticAnalysis`
- [ ] 撰寫測試使用 mock Gemini client
- [ ] 撰寫測試確認 prompt 內容
- [ ] 撰寫測試確認合法 JSON 可解析
- [ ] 撰寫測試確認 malformed JSON fallback
- [ ] 撰寫測試確認 API failure fallback
- [ ] 撰寫測試確認測試不會真的呼叫網路
- [ ] 執行 `uv run pytest tests/test_gemini_analyzer.py`

## 驗收條件

- [ ] Gemini API 細節只存在此 module
- [ ] 正常回應會轉成 `SemanticAnalysis`
- [ ] 單一 evidence 失敗不影響其他 evidence
- [ ] 測試不需要真實 Gemini API key
- [ ] `uv run pytest tests/test_gemini_analyzer.py` 通過

## 不做的事

- [ ] 不產生風險分數
- [ ] 不產生 PQC 建議
- [ ] 不輸出報告檔案
