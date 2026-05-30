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

## 啟動前端

在專案目錄執行：

```bash
uv run python server.py
```

然後開啟：

```text
http://localhost:8000/index.html
```

前端輸入欄請填入 `.git` clone URL，例如：

```text
https://github.com/owner/repo.git
```

前端目前使用 static analysis fallback，不需要 Gemini API key。

如果你要直接用 uvicorn CLI，WSL 或跨環境瀏覽器建議明確指定 host：

```bash
uv run uvicorn server:app --reload --host 0.0.0.0 --port 8000
```

## 支援語言

目前支援 rule-based static scanning：

| 語言 | 副檔名 | 主要偵測目標 |
| --- | --- | --- |
| Python | `.py` | `cryptography`、`ssl`、PyCryptodome、`hashlib`、`hmac`、RSA/ECC/ECDH/DH/AES/SHA/HMAC 關鍵字 |
| JavaScript / TypeScript | `.js`、`.jsx`、`.ts`、`.tsx` | Node.js `crypto`、WebCrypto、`jose`、`jsonwebtoken`、`node-forge`、RSA/ECDSA/ECDH/DH/AES/SHA/HMAC pattern |
| Java | `.java` | JCA/JCE、KeyStore、JSSE TLS config、BouncyCastle：`KeyPairGenerator`、`Cipher`、`Signature`、`KeyAgreement`、`MessageDigest`、`Mac`、`SSLContext` |
| C / C++ | `.c`、`.cc`、`.cpp`、`.cxx`、`.h`、`.hh`、`.hpp`、`.hxx` | OpenSSL classic APIs 與 EVP APIs：`RSA_generate_key_ex`、`EVP_PKEY_*`、`EVP_DigestSign*`、`EVP_DigestVerify*`、`EVP_PKEY_derive/encrypt/decrypt`、`EVP_sha*`、`HMAC`、`EVP_aes_*`、`EC_KEY_*`、`ECDSA_*`、`ECDH_*`、`DH_*` |

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
