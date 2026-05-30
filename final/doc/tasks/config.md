# config.py 任務

## 目標

建立集中式設定物件，管理 target path、output directory、report format、Gemini API key、Gemini model、snippet 限制與 skip AI 模式。

## 輸入依據

- `doc/final_project_proposal.md`
- `doc/detailed-design.md`

## 輸出

- `src/pqc_audit/config.py`
- `tests/test_config.py`

## 最小可執行任務

- [ ] 定義 `AppConfig` 資料結構
- [ ] 加入 `target_path` 欄位
- [ ] 加入 `output_dir` 欄位
- [ ] 加入 `report_format` 欄位，允許 `markdown`、`json`、`both`
- [ ] 加入 `gemini_api_key` 欄位
- [ ] 加入 `gemini_model` 欄位
- [ ] 加入 `max_snippet_lines` 欄位
- [ ] 加入 `skip_ai` 欄位
- [ ] 實作從 `GEMINI_API_KEY` 讀取 API key 的函式
- [ ] 實作預設 Gemini model
- [ ] 實作設定驗證：target path 必須存在
- [ ] 實作設定驗證：target path 必須是資料夾
- [ ] 實作設定驗證：report format 必須是允許值
- [ ] 實作設定驗證：AI 啟用時必須有 Gemini API key
- [ ] 實作設定驗證：`skip_ai=True` 時允許缺少 Gemini API key
- [ ] 撰寫測試確認預設值
- [ ] 撰寫測試確認 environment variable 載入
- [ ] 撰寫測試確認缺少 Gemini API key 的錯誤行為
- [ ] 撰寫測試確認 `skip_ai=True` 不需要 API key
- [ ] 執行 `uv run pytest tests/test_config.py`

## 驗收條件

- [ ] 所有 runtime 設定集中在 `AppConfig`
- [ ] 缺少 Gemini API key 時的行為符合設計
- [ ] 測試不需要網路
- [ ] `uv run pytest tests/test_config.py` 通過

## 不做的事

- [ ] 不解析 CLI argument
- [ ] 不建立 output report
- [ ] 不呼叫 Gemini API
