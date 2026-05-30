# migration_recommender.py 任務

## 目標

根據 algorithm、usage type 與 risk assessment 產生可行的 PQC 遷移建議，輸出 `MigrationRecommendation`。

## 輸入依據

- `doc/final_project_proposal.md`
- `doc/detailed-design.md`

## 輸出

- `src/pqc_audit/migration_recommender.py`
- `tests/test_migration_recommender.py`

## 最小可執行任務

- [ ] 建立 `MigrationRecommender` 類別
- [ ] 實作 `recommend(evidence_items, analyses, risks)` 介面
- [ ] 以 `evidence_id` 對齊 evidence、analysis 與 risk
- [ ] RSA encryption / key transport 建議 ML-KEM 或 hybrid key establishment
- [ ] RSA signature 建議 ML-DSA 或 SLH-DSA
- [ ] ECDH key exchange 建議 PQC KEM 或 hybrid key exchange
- [ ] DH key exchange 建議 PQC KEM 或 hybrid key exchange
- [ ] ECDSA signature 建議 ML-DSA 或 SLH-DSA
- [ ] DSA signature 建議 ML-DSA 或 SLH-DSA
- [ ] TLS configuration 建議檢查 TLS stack 是否支援 PQC 或 hybrid key exchange
- [ ] Certificate handling 建議檢查憑證鏈與簽章演算法需求
- [ ] Unknown usage 建議人工確認 cryptographic context
- [ ] 每筆 recommendation 產生 `summary`
- [ ] 每筆 recommendation 產生 `recommended_action`
- [ ] 每筆 recommendation 產生 `candidate_pqc_algorithms`
- [ ] 每筆 recommendation 產生 `compatibility_notes`
- [ ] 每筆 recommendation 產生 `developer_steps`
- [ ] high-risk finding 必須有非空 `recommended_action`
- [ ] 撰寫測試確認 RSA key exchange 建議
- [ ] 撰寫測試確認 ECDSA signature 建議
- [ ] 撰寫測試確認 TLS 建議
- [ ] 撰寫測試確認 unknown usage 建議
- [ ] 撰寫測試確認 high-risk finding 有 action
- [ ] 執行 `uv run pytest tests/test_migration_recommender.py`

## 驗收條件

- [ ] 每個 finding 都有 `MigrationRecommendation`
- [ ] 建議內容符合詳細設計中的對照表
- [ ] 不呼叫 Gemini
- [ ] 測試不需要網路
- [ ] `uv run pytest tests/test_migration_recommender.py` 通過

## 不做的事

- [ ] 不自動修改程式碼
- [ ] 不產生 patch
- [ ] 不驗證實際 library 是否支援 PQC
