# risk_assessor.py 任務

## 目標

根據 `CryptoEvidence` 與 `SemanticAnalysis` 進行量子風險分類與風險分數計算，輸出 `RiskAssessment`。

## 輸入依據

- `doc/final_project_proposal.md`
- `doc/detailed-design.md`

## 輸出

- `src/pqc_audit/risk_assessor.py`
- `tests/test_risk_assessor.py`

## 最小可執行任務

- [ ] 建立 `RiskAssessor` 類別
- [ ] 實作 `assess(evidence_items, analyses)` 介面
- [ ] 以 `evidence_id` 對齊 evidence 與 semantic analysis
- [ ] Gemini 判斷不是真實 crypto usage 時輸出 `unknown`
- [ ] RSA 分類為 `quantum_vulnerable`
- [ ] ECC 分類為 `quantum_vulnerable`
- [ ] ECDSA 分類為 `quantum_vulnerable`
- [ ] ECDH 分類為 `quantum_vulnerable`
- [ ] DH 分類為 `quantum_vulnerable`
- [ ] DSA 分類為 `quantum_vulnerable`
- [ ] TLS configuration 且 public-key algorithm unknown 時分類為 `partially_vulnerable`
- [ ] Certificate handling 且 public-key algorithm unknown 時分類為 `partially_vulnerable`
- [ ] AES 類 symmetric algorithm 分類為 `quantum_safe`
- [ ] SHA-256 類 hash algorithm 分類為 `quantum_safe`
- [ ] Unknown algorithm 但 security-sensitive 時分類為 `unknown`
- [ ] 實作 base score
- [ ] usage type 為 `key_exchange` 時調整分數
- [ ] usage type 為 `signature` 時調整分數
- [ ] usage type 為 `key_generation` 時調整分數
- [ ] test/example usage 時降低分數
- [ ] Gemini confidence 過低時降低分數
- [ ] 將 score 限制在 `0..100`
- [ ] 產生 `risk_factors`
- [ ] 產生人類可讀 `reason`
- [ ] 缺少 semantic analysis 時使用 static evidence fallback
- [ ] 撰寫測試確認 RSA 風險
- [ ] 撰寫測試確認 ECDH 風險
- [ ] 撰寫測試確認 TLS unknown partial risk
- [ ] 撰寫測試確認 test/example score reduction
- [ ] 撰寫測試確認 score clamping
- [ ] 撰寫測試確認 missing semantic analysis fallback
- [ ] 執行 `uv run pytest tests/test_risk_assessor.py`

## 驗收條件

- [ ] 風險分類符合詳細設計
- [ ] 分數永遠在 `0..100`
- [ ] 不呼叫 Gemini
- [ ] 測試不需要網路
- [ ] `uv run pytest tests/test_risk_assessor.py` 通過

## 不做的事

- [ ] 不產生 Gemini prompt
- [ ] 不產生 PQC 建議
- [ ] 不輸出報告檔案
