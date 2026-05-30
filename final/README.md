# AI 輔助密碼學稽核與 PQC 遷移建議工具

這是一個多語言 MVP 工具，用來掃描本地專案中的傳統公鑰密碼學使用情況，找出可能受到量子運算威脅的 RSA、ECC、ECDSA、ECDH、DH 等使用，並產生後量子密碼學（PQC）遷移建議。

工具流程：

1. 掃描支援語言的原始碼
2. 偵測 cryptographic API 與演算法關鍵字
3. 萃取相關程式碼片段
4. 使用 Gemini API 做語意分析，或使用 `--skip-ai` 跳過 AI
5. 產生量子風險評估
6. 產生 PQC 遷移建議
7. 輸出 Markdown 與 JSON 報告

## 核心技術

- **多語言 repository scanner**：載入本地或前端 clone 下來的 repository，忽略 `.git`、`.venv`、cache、build artifacts 等不需要分析的目錄。
- **Rule-based static cryptographic scanner**：針對 Python、JavaScript/TypeScript、Java、C/C++ 偵測 RSA、ECC、ECDSA、ECDH、DH、AES、SHA、HMAC、TLS config、certificate handling 與常見 cryptographic library API。
- **Evidence extraction**：將 static match 轉成帶有檔案路徑、行號、程式碼片段、演算法、library、usage type 的 `CryptoEvidence`，讓後續分析不需要讀完整 source file。
- **Gemini semantic analysis**：在非 `--skip-ai` 模式下，使用 Gemini API 判斷 evidence 是否是真實 cryptographic usage、是否 security-sensitive、是否是 test/example code，並支援 retry/backoff。
- **Static fallback analysis**：在 `--skip-ai` 或前端模式下，不依賴 API key，直接根據 static evidence 產生保守分析結果。
- **Quantum risk assessment**：根據演算法、用途、security sensitivity、test/example signal、evidence type、confidence 產生 `quantum_vulnerable`、`partially_vulnerable`、`quantum_safe` 或 `unknown` 風險等級與分數。
- **PQC migration recommendation**：依照風險與用途產生 ML-KEM、ML-DSA、SLH-DSA、hybrid migration 等候選遷移建議。
- **Markdown / JSON report generator**：輸出人工可讀的 Markdown 報告與可供前端或其他工具整合的 JSON schema。
- **FastAPI web UI**：提供 `/index.html` 前端與 `/api/scan` API，可輸入 `.git` clone URL 後直接分析並視覺化 findings。

## 環境需求

- Python 3.11+
- `uv`

## Web 介面：輸入 GitHub Repo 連結分析

本專案也提供一個簡易 Web 介面，可以透過瀏覽器輸入 GitHub repository 連結，後端會自動：

1. Clone 指定的 GitHub repository
2. 執行 `pqc-audit` 掃描
3. 產生 JSON 報告
4. 將分析結果回傳到網頁顯示

### Web 介面額外需求

除了原本的環境需求之外，使用 Web 介面還需要：

- Git
- 可連線到 GitHub
- FastAPI
- Uvicorn
- 若使用 Gemini 分析，需要有效的 `GEMINI_API_KEY`

### 安裝依賴

第一次使用前，請先同步 uv 環境：

```bash
uv sync
```

請確認 `pyproject.toml` 的 `dependencies` 內包含 `fastapi` 與 `uvicorn[standard]`，例如：

```toml
dependencies = [
    "fastapi>=0.116.0",
    "mypy>=2.1.0",
    "pytest>=9.0.3",
    "ruff>=0.15.15",
    "uvicorn[standard]>=0.48.0",
]
```

如果修改過 `pyproject.toml`，請重新執行：

```bash
uv sync
```

### 啟動 Web App

在專案根目錄執行：

```bash
uv run server.py
```

啟動後會開啟本地網站：

```text
http://127.0.0.1:8000
```

如果瀏覽器沒有自動開啟，可以手動打開：

```text
http://127.0.0.1:8000
```

### 使用方式

1. 開啟網頁
2. 在輸入框貼上 GitHub repository URL，例如：

```text
https://github.com/example/example-python-project
```

3. 按下分析按鈕
4. 系統會自動 clone repository 並執行 PQC 稽核
5. 分析完成後，網頁會顯示掃描結果

### Web API

Web 介面會呼叫後端 API：

```text
POST /api/scan
```

Request body 範例：

```json
{
  "repo_url": "https://github.com/example/example-python-project"
}
```

後端會：

1. 建立暫存資料夾
2. 使用 `git clone` 下載目標 repository
3. 執行：

```bash
uv run pqc-audit --target <repo_dir> --output <report_dir> --format json
```

4. 讀取產生的 `security-report.json`
5. 將 JSON 結果回傳給前端
6. 掃描完成後自動清除暫存資料夾

### Web 專案結構

目前 Web 介面需要以下檔案存在於專案根目錄：

```text
.
├── index.html
├── server.py
├── pyproject.toml
├── uv.lock
├── src/
├── tests/
└── reports/
```

其中：

- `index.html`：前端頁面
- `server.py`：FastAPI 後端服務
- `src/`：`pqc-audit` CLI 工具原始碼
- `reports/`：本地掃描報告輸出資料夾

### Web 介面注意事項

- Web 模式預設會呼叫後端的 `pqc-audit` 指令。
- 如果沒有使用 `--skip-ai`，請先確認 `.env` 中已設定：

```text
GEMINI_API_KEY=你的 Gemini API key
```

- 後端會暫時 clone GitHub repository 到系統暫存資料夾。
- 掃描完成後，暫存資料夾會自動刪除。
- 如果在 WSL、Docker、Remote Container 或無 GUI 的 Linux 環境中執行，瀏覽器可能不會自動開啟。此時請手動在瀏覽器中開啟：

```text
http://127.0.0.1:8000
```

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

## 快速開始：使用 Web 介面分析 GitHub Repository

如果要透過網頁輸入 GitHub repository 連結並執行分析：

```bash
uv run server.py
```

接著開啟：

```text
http://127.0.0.1:8000
```

在網頁中輸入 GitHub repository URL 後即可開始分析。

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

## 掃描其他專案

將 `--target` 指向要掃描的專案資料夾：

```bash
uv run pqc-audit --target /path/to/project --output ./reports --format both --skip-ai
```

## CLI 參數

| 參數 | 必填 | 說明 |
| --- | --- | --- |
| `--target` | 是 | 要掃描的專案資料夾 |
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
- finding category、confidence、evidence type、source kind
- 量子風險分數
- 風險原因
- PQC 遷移建議

## 注意事項

- MVP 目前支援 Python、JavaScript/TypeScript、Java、C/C++ source files。
- JavaScript/TypeScript、Java、C/C++ 目前使用 regex-based rule scanning，不做語言 AST parser。
- `--skip-ai` 模式不會呼叫 Gemini，因此語意判斷較保守。
- Gemini 模式需要有效的 `GEMINI_API_KEY`，可從 shell environment 或 `.env` 載入。
- 工具只產生稽核報告與建議，不會自動修改被掃描的專案程式碼。
