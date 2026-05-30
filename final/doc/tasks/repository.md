# repository.py 任務

## 目標

讀取本地端 Python 專案，找出可掃描的 `.py` 檔案，忽略不相關資料夾，並回傳 `SourceFile` 清單。

## 輸入依據

- `doc/final_project_proposal.md`
- `doc/detailed-design.md`

## 輸出

- `src/pqc_audit/repository.py`
- `tests/test_repository.py`

## 最小可執行任務

- [ ] 實作 target path 存在性檢查
- [ ] 實作 target path 必須是資料夾的檢查
- [ ] 實作 `.py` 檔案搜尋
- [ ] 忽略 `.git`
- [ ] 忽略 `.venv`
- [ ] 忽略 `venv`
- [ ] 忽略 `env`
- [ ] 忽略 `__pycache__`
- [ ] 忽略 `.mypy_cache`
- [ ] 忽略 `.pytest_cache`
- [ ] 忽略 `node_modules`
- [ ] 忽略 `dist`
- [ ] 忽略 `build`
- [ ] 實作讀取單一 Python 檔案為 `SourceFile`
- [ ] 計算 `relative_path`
- [ ] 計算 `line_count`
- [ ] 將單一檔案讀取失敗記錄為 recoverable error
- [ ] 撰寫測試確認只回傳 `.py` 檔案
- [ ] 撰寫測試確認 ignored directories 不會被掃描
- [ ] 撰寫測試確認 `SourceFile.relative_path`
- [ ] 撰寫測試確認不存在 target path 會失敗
- [ ] 撰寫測試確認 target path 不是資料夾會失敗
- [ ] 執行 `uv run pytest tests/test_repository.py`

## 驗收條件

- [ ] 可以載入本地 Python 專案
- [ ] 不會掃描設計中列出的 ignored directories
- [ ] 回傳資料使用 `SourceFile`
- [ ] 測試不需要 Gemini API 或網路
- [ ] `uv run pytest tests/test_repository.py` 通過

## 不做的事

- [ ] 不 clone GitHub repository
- [ ] 不掃描 Python 以外的語言
- [ ] 不分析檔案內容是否有密碼學使用
