# pipeline.py 任務

## 目標

串接所有 module，按照設計中的 pipeline 執行完整掃描、分析、風險評估、建議與報告產生流程。

## 輸入依據

- `doc/final_project_proposal.md`
- `doc/detailed-design.md`

## 輸出

- `src/pqc_audit/pipeline.py`
- `tests/test_pipeline.py`

## 最小可執行任務

- [ ] 建立 `AuditPipeline` 類別
- [ ] 實作 `run(config)` 介面
- [ ] 呼叫 repository module 載入 Python 檔案
- [ ] 呼叫 static scanner 產生 `StaticMatch`
- [ ] 呼叫 pattern extractor 產生 `CryptoEvidence`
- [ ] `skip_ai=False` 時呼叫 Gemini analyzer
- [ ] `skip_ai=True` 時不呼叫 Gemini analyzer
- [ ] `skip_ai=True` 時產生 static fallback `SemanticAnalysis`
- [ ] 呼叫 risk assessor 產生 `RiskAssessment`
- [ ] 呼叫 migration recommender 產生 `MigrationRecommendation`
- [ ] 組合 `Finding`
- [ ] 呼叫 report generator 建立 `AuditReport`
- [ ] `report_format=markdown` 時只輸出 Markdown
- [ ] `report_format=json` 時只輸出 JSON
- [ ] `report_format=both` 時同時輸出 Markdown 與 JSON
- [ ] 收集 recoverable errors 並放入 report
- [ ] fatal error 直接停止並回傳清楚錯誤
- [ ] 撰寫測試 mock 各 module 並確認執行順序
- [ ] 撰寫測試確認 `skip_ai=True` 不呼叫 Gemini
- [ ] 撰寫測試確認 report format routing
- [ ] 撰寫測試確認 pipeline 回傳 `AuditReport`
- [ ] 撰寫測試確認 recoverable errors 會進入 report
- [ ] 執行 `uv run pytest tests/test_pipeline.py`

## 驗收條件

- [ ] pipeline 順序符合詳細設計
- [ ] `skip_ai` 行為符合詳細設計
- [ ] report format 行為符合 CLI 設計
- [ ] 測試不需要真實 Gemini API key
- [ ] `uv run pytest tests/test_pipeline.py` 通過

## 不做的事

- [ ] 不在 pipeline 中實作 scanner rule
- [ ] 不在 pipeline 中實作 Gemini prompt
- [ ] 不在 pipeline 中格式化報告內容
