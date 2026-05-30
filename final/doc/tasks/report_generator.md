# report_generator.py 任務

## 目標

組合完整 `AuditReport`，並輸出 Markdown 與 JSON 兩種 final security report。

## 輸入依據

- `doc/final_project_proposal.md`
- `doc/detailed-design.md`

## 輸出

- `src/pqc_audit/report_generator.py`
- `tests/test_report_generator.py`

## 最小可執行任務

- [ ] 建立 `ReportGenerator` 類別
- [ ] 實作 `generate(target_path, findings, errors)` 介面
- [ ] 產生 `generated_at`
- [ ] 統計 total findings
- [ ] 統計 `quantum_vulnerable`
- [ ] 統計 `partially_vulnerable`
- [ ] 統計 `quantum_safe`
- [ ] 統計 `unknown`
- [ ] 組合 `AuditReport`
- [ ] 實作 `write_markdown(report, output_path)`
- [ ] Markdown 包含 title
- [ ] Markdown 包含 scan summary
- [ ] Markdown 包含 risk summary
- [ ] Markdown 包含 findings table
- [ ] Markdown 包含 detailed findings
- [ ] Markdown 包含 errors and skipped files
- [ ] Markdown 包含 migration summary
- [ ] 實作 `write_json(report, output_path)`
- [ ] JSON 包含 target path
- [ ] JSON 包含 generated_at
- [ ] JSON 包含 summary
- [ ] JSON 包含 findings
- [ ] JSON 包含 errors
- [ ] 確保 JSON 可被 `json.loads` 解析
- [ ] output directory 不存在時建立
- [ ] 撰寫測試確認 Markdown 檔案內容
- [ ] 撰寫測試確認 JSON 檔案合法
- [ ] 撰寫測試確認 summary counts
- [ ] 撰寫測試確認 empty report 行為
- [ ] 撰寫測試確認 report generation 不需要 Gemini
- [ ] 執行 `uv run pytest tests/test_report_generator.py`

## 驗收條件

- [ ] 可以產生 `security-report.md`
- [ ] 可以產生 `security-report.json`
- [ ] JSON 結構符合詳細設計
- [ ] Markdown 適合人類閱讀
- [ ] 測試不需要網路
- [ ] `uv run pytest tests/test_report_generator.py` 通過

## 不做的事

- [ ] 不執行掃描
- [ ] 不呼叫 Gemini
- [ ] 不評估風險
