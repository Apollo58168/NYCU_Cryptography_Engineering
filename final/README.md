# AI 輔助密碼學稽核與 PQC 遷移建議工具

這是一個 Python-only MVP 工具，用來掃描本地 Python 專案中的傳統公鑰密碼學使用情況，找出可能受到量子運算威脅的 RSA、ECC、ECDSA、ECDH、DH 等使用，並產生後量子密碼學（PQC）遷移建議。

工具流程：

1. 掃描 Python 原始碼
2. 偵測 cryptographic API 與演算法關鍵字
3. 萃取相關程式碼片段
4. 使用 Gemini API 做語意分析，或使用 `--skip-ai` 跳過 AI
5. 產生量子風險評估
6. 產生 PQC 遷移建議
7. 輸出 Markdown 與 JSON 報告

## 環境需求

- Python 3.11+
- `uv`

## 執行測試

在專案目錄執行：

```bash
uv run pytest
```

可選擇執行 lint：

```bash
uv run ruff check .
```

## 快速開始：不使用 Gemini

如果只想先用靜態分析模式執行，不需要 Gemini API key：

```bash
uv run pqc-audit --target . --output ./reports --format both --skip-ai
```

執行完成後會產生：

```text
./reports/security-report.md
./reports/security-report.json
```

## 使用 Gemini API

如果要啟用 AI 語意分析，建議先複製 `.env.example`：

```bash
cp .env.example .env
```

接著編輯 `.env`，把 placeholder 換成自己的 Gemini API key：

```text
GEMINI_API_KEY=你的 Gemini API key
```

`.env` 已加入 `.gitignore`，不要提交到 git。

設定完成後執行：

```bash
uv run pqc-audit --target . --output ./reports --format both
```

預設 Gemini model 是：

```text
gemini-2.5-flash
```

如果要指定其他 model，可以使用 `--gemini-model`：

```bash
uv run pqc-audit \
  --target . \
  --output ./reports \
  --format both \
  --gemini-model gemini-2.5-flash
```

也可以不用 `.env`，直接用 shell environment：

```bash
export GEMINI_API_KEY="你的 Gemini API key"
uv run pqc-audit --target . --output ./reports --format both
```

如果同時存在 shell environment 和 `.env`，shell environment 的 `GEMINI_API_KEY` 會優先使用。

## 掃描其他 Python 專案

將 `--target` 指向要掃描的 Python 專案資料夾：

```bash
uv run pqc-audit --target /path/to/python_project --output ./reports --format both --skip-ai
```

## CLI 參數

| 參數 | 必填 | 說明 |
| --- | --- | --- |
| `--target` | 是 | 要掃描的 Python 專案資料夾 |
| `--output` | 是 | 報告輸出資料夾 |
| `--format` | 否 | `markdown`、`json` 或 `both`，預設為 `both` |
| `--max-snippet-lines` | 否 | 每個 evidence snippet 的最大行數，預設為 `40` |
| `--gemini-model` | 否 | Gemini model，預設為 `gemini-2.5-flash` |
| `--skip-ai` | 否 | 跳過 Gemini，只使用 static analysis fallback |

## 輸出報告

Markdown 報告適合人工閱讀：

```text
security-report.md
```

JSON 報告適合後續工具整合：

```text
security-report.json
```

報告內容包含：

- 掃描目標
- finding 數量
- 風險等級統計
- 檔案路徑與行號
- 偵測到的演算法與用途
- 量子風險分數
- 風險原因
- PQC 遷移建議

## 注意事項

- MVP 目前只支援 Python source files。
- `--skip-ai` 模式不會呼叫 Gemini，因此語意判斷較保守。
- Gemini 模式需要有效的 `GEMINI_API_KEY`，可從 shell environment 或 `.env` 載入。
- 工具只產生稽核報告與建議，不會自動修改被掃描的專案程式碼。
