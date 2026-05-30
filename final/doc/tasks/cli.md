# cli.py 任務

## 目標

提供 command-line interface，讓使用者可以指定目標專案、輸出資料夾、報告格式與是否跳過 AI 分析。

## 輸入依據

- `doc/final_project_proposal.md`
- `doc/detailed-design.md`

## 輸出

- `src/pqc_audit/cli.py`
- `tests/test_cli.py`

## 最小可執行任務

- [ ] 建立 CLI entry function
- [ ] 使用標準函式庫 `argparse` 或專案已採用的 CLI 工具
- [ ] 實作 `--target` argument
- [ ] 實作 `--output` argument
- [ ] 實作 `--format` argument，允許 `markdown`、`json`、`both`
- [ ] 實作 `--max-snippet-lines` argument
- [ ] 實作 `--skip-ai` flag
- [ ] 將 CLI arguments 轉成 `AppConfig`
- [ ] 呼叫 `AuditPipeline.run(config)`
- [ ] 成功時印出報告輸出位置
- [ ] fatal error 時印出清楚錯誤訊息
- [ ] fatal error 時回傳非 0 exit code
- [ ] 成功時回傳 0 exit code
- [ ] 在 `pyproject.toml` 加入 CLI script entry point
- [ ] 撰寫測試確認 argument parsing
- [ ] 撰寫測試確認 invalid report format
- [ ] 撰寫測試 mock pipeline 並確認 config 傳入正確
- [ ] 撰寫測試確認成功 exit code
- [ ] 撰寫測試確認錯誤 exit code
- [ ] 執行 `uv run pytest tests/test_cli.py`

## 驗收條件

- [ ] 可以執行 `pqc-audit --target ./example_project --output ./reports --format both`
- [ ] CLI 不直接實作掃描與分析邏輯
- [ ] CLI 可用 mock pipeline 做單元測試
- [ ] `uv run pytest tests/test_cli.py` 通過

## 不做的事

- [ ] 不直接讀取 source files
- [ ] 不直接呼叫 Gemini API
- [ ] 不直接組合 Markdown 或 JSON 報告
