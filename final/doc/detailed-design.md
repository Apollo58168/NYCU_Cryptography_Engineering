# Final Project：AI 輔助密碼學稽核與後量子密碼遷移框架

## 1. 專案名稱

**AI-Assisted Cryptographic Auditing and Post-Quantum Cryptography Migration Framework**  
**AI 輔助密碼學稽核與後量子密碼遷移框架**

---

## 2. 專案概述

本專案希望設計並實作一套 **AI 輔助的密碼學安全稽核框架**，用來自動掃描軟體專案中的密碼學使用情況，找出可能受到量子運算威脅的傳統公鑰密碼演算法，並進一步產生後量子密碼學（Post-Quantum Cryptography, PQC）的遷移建議。

目前許多現代軟體系統仍然依賴 RSA、ECC、Diffie-Hellman 等傳統公鑰密碼演算法。這些演算法在傳統電腦上仍然被認為是安全的，因為它們建立在大數分解、離散對數、橢圓曲線離散對數等難以有效求解的數學問題之上。然而，隨著量子運算的發展，Shor's Algorithm 已被證明可以在足夠強大的量子電腦上，以多項式時間破解這些數學問題。

因此，若未來量子硬體逐漸成熟，現有大量依賴傳統公鑰密碼的系統可能面臨安全風險。本專案的目標就是建立一個結合 **靜態程式分析** 與 **AI 語意分析** 的工具，協助開發者快速找出程式碼中潛在的量子不安全密碼學使用，並提供實用的 PQC 遷移方向。

---

## 3. 專案動機

許多現代系統仍然使用 RSA、ECC 等傳統密碼演算法。這些演算法廣泛存在於 TLS、安全通訊、數位簽章、憑證驗證、金鑰交換與身分驗證機制中。

然而，實際軟體專案中的密碼學使用通常非常分散，可能出現在：

- 原始碼中的 cryptographic API 呼叫
- TLS 或 SSL 設定
- 憑證載入與驗證邏輯
- 第三方 library 包裝過的 helper function
- 設定檔或部署腳本
- 測試程式或範例程式碼

這使得人工稽核變得非常困難。安全工程師若要手動檢查大型 codebase 中所有密碼學相關使用，不僅耗時，也容易遺漏隱藏在不同模組中的風險。

因此，本專案提出一個 AI 輔助框架，希望達成以下目標：

- 自動偵測程式碼中的傳統密碼學使用
- 判斷該使用是否可能受到量子攻擊影響
- 產生量子風險評估結果
- 提供後量子密碼學遷移建議
- 降低人工安全稽核成本

---

## 4. 技術背景

### 4.1 傳統公鑰密碼學

目前產業界廣泛使用的公鑰密碼演算法包含：

- **RSA**
- **ECC**
- **ECDSA**
- **ECDH**
- **Diffie-Hellman**
- **DSA**

這些演算法被用於許多安全場景，例如：

- RSA 加密與數位簽章
- ECDSA 數位簽章
- ECDH 金鑰交換
- Diffie-Hellman 金鑰交換
- TLS 憑證與握手流程
- 公私鑰產生與驗證

在傳統電腦上，RSA 的安全性主要依賴大數分解問題，而 ECC、ECDSA、ECDH、Diffie-Hellman 則依賴離散對數或橢圓曲線離散對數問題。這些問題對傳統電腦而言非常困難，因此目前仍被廣泛使用。

### 4.2 量子運算帶來的威脅

Shor's Algorithm 顯示，如果未來出現足夠穩定且大規模的量子電腦，RSA、ECC、Diffie-Hellman 等傳統公鑰密碼演算法可能被有效破解。

這代表目前許多系統中使用的傳統公鑰密碼機制，在未來可能不再安全。尤其是以下情境風險較高：

- 長期保存的機密資料
- 需要長期安全性的通訊內容
- 使用 RSA 或 ECC 的數位簽章
- 使用 ECDH 或 DH 的金鑰交換
- TLS 或憑證系統中的傳統公鑰演算法

### 4.3 後量子密碼學

後量子密碼學（Post-Quantum Cryptography, PQC）是指能夠抵抗量子電腦攻擊的密碼學演算法。常見的 PQC 遷移方向包括：

- 使用後量子金鑰封裝機制，例如 **ML-KEM**
- 使用後量子數位簽章，例如 **ML-DSA** 或 **SLH-DSA**
- 採用 classical + PQC 的 hybrid migration strategy
- 在 TLS 或其他協定層級導入 PQC-ready 的金鑰交換流程

不過，PQC 遷移不能只是單純替換一個 API。實際上，密碼學演算法通常和協定、憑證格式、client/server 相容性、library 支援度有關。因此，開發者需要一個能夠指出風險並提供清楚遷移方向的工具。

---

## 5. 問題定義

本專案想解決的核心問題如下：

### 5.1 傳統密碼學演算法散落在大型 codebase 中

RSA、ECC、Diffie-Hellman 等演算法可能出現在不同檔案、不同 library、不同設定邏輯中。開發者很難用人工方式完整找出所有相關使用。

### 5.2 傳統公鑰密碼可能受到量子運算威脅

隨著量子運算發展，傳統公鑰密碼演算法可能逐漸不再適合作為長期安全保護機制。

### 5.3 人工安全稽核成本高且不易擴展

大型專案可能有上千個檔案，若要逐一檢查所有密碼學相關使用，會花費大量時間與人力，而且不同工程師的判斷也可能不一致。

### 5.4 開發者缺乏明確的 PQC 遷移建議

即使找出了 RSA 或 ECC 的使用，開發者也不一定知道下一步該怎麼做。例如：

- 這段程式碼是否真的有安全風險？
- 它是測試碼還是 production code？
- 它用於加密、簽章、金鑰交換，還是憑證處理？
- 應該使用哪一類 PQC 替代方案？
- 是否需要 hybrid migration？
- 是否需要修改協定層級？

因此，本專案希望讓工具不只偵測問題，也能產生具體、可理解的遷移建議。

---

## 6. 系統流程

本專案的系統 pipeline 可分成七個階段：

1. Source Code Repository
2. Static Code Scanner
3. Cryptographic Pattern Extraction
4. AI Semantic Analysis
5. Quantum Risk Assessment
6. PQC Migration Suggestion
7. Final Security Report

---

## 7. 系統架構詳細說明

### 7.1 Source Code Repository

系統輸入是一個軟體專案的原始碼 repository，可以是：

- GitHub 專案
- 本地端專案資料夾
- 開源專案
- 使用者自己的 Python 專案

在 MVP 版本中，系統主要以 **本地端 Python 專案** 為掃描目標。工具會讀取專案目錄中的 `.py` 檔案，並略過不相關的資料夾，例如 `.git`、`.venv`、`__pycache__`、`build`、`dist` 等。

### 7.2 Static Code Scanner

第一階段會使用靜態程式掃描器找出可能與密碼學相關的程式碼。

這一階段可以使用：

- Regular Expression
- Python AST analysis
- 關鍵字比對
- API pattern matching

目標是快速找出可能的 cryptographic API usage，例如：

- `rsa.generate_private_key`
- `ec.generate_private_key`
- `dh.generate_parameters`
- `ssl.SSLContext`
- `ssl.create_default_context`
- `Crypto.PublicKey.RSA`
- `Cryptodome.PublicKey.RSA`
- 字串中出現 RSA、ECC、ECDSA、ECDH、Diffie-Hellman 等演算法名稱

這個階段的重點是 **快速過濾**。它不一定要百分之百判斷程式碼是否真的有安全風險，而是先找出可疑區塊，降低後續 AI 分析的成本。

### 7.3 Cryptographic Pattern Extraction

當 Static Scanner 找到可疑的程式碼行後，系統會進一步萃取密碼學使用模式。

這一階段會整理出結構化的 evidence，例如：

- 檔案路徑
- 起始行號與結束行號
- 相關程式碼片段
- 可能的演算法名稱
- 可能使用的 library
- 初步推測的使用類型
- 對應的靜態掃描規則

例如，如果系統偵測到：

```python
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
```

它可能會萃取出：

```text
Algorithm: RSA
Usage Type: key_generation
Library: cryptography
Risk Hint: high
```

這個階段的目標是把原始程式碼轉換成更容易被 AI 與後續模組理解的結構化資料。

### 7.4 AI Semantic Analysis

靜態分析雖然快速，但容易產生 false positive。例如，程式碼中可能只是在 comment 裡提到 RSA，或是在測試程式中示範 ECC 使用，並不一定代表 production code 真的有風險。

因此，本專案會使用 LLM 進行語意分析。在實作設計中，AI semantic analysis module 預計使用 **Gemini API**。

AI 模組會針對每個 evidence 判斷：

- 這是否是真正的密碼學使用？
- 這是否是安全敏感的程式碼？
- 使用的是哪一種演算法？
- 用途是加密、簽章、金鑰交換、金鑰產生、憑證處理，還是 TLS 設定？
- 這段程式碼是 production code、test code，還是 example code？
- 它是否可能受到量子攻擊影響？
- 判斷信心程度是多少？

AI 分析可以補足靜態規則的不足，讓系統不只是看關鍵字，而是理解程式碼的上下文。

### 7.5 Quantum Risk Assessment

完成 AI 語意分析後，系統會進行量子風險評估。

風險分類可以分為：

- **quantum_safe**：目前看起來不屬於量子脆弱的公鑰密碼使用，或使用的是對量子攻擊較不敏感的對稱式演算法。
- **partially_vulnerable**：風險取決於上下文，例如 TLS 設定或憑證處理中未明確指出使用哪種公鑰演算法。
- **quantum_vulnerable**：使用 RSA、ECC、ECDSA、ECDH、DH、DSA 等可能受到 Shor's Algorithm 影響的演算法。
- **unknown**：資訊不足，需要人工確認。

風險分數可以根據以下因素調整：

- 演算法類型
- 使用場景
- 是否為金鑰交換
- 是否為數位簽章
- 是否為金鑰產生
- 是否涉及長期秘密
- 是否只是測試或範例
- AI 判斷信心程度

例如：

```text
RSA key generation:
Risk Level: quantum_vulnerable
Risk Score: 95
Reason: RSA relies on integer factorization, which can be broken by Shor's Algorithm on a sufficiently powerful quantum computer.
```

### 7.6 PQC Migration Suggestion

風險評估完成後，系統會產生 PQC 遷移建議。

遷移建議會根據演算法與用途而不同：

| 偵測到的使用情況               | 建議方向                                           |
| ------------------------------ | -------------------------------------------------- |
| RSA encryption / key transport | 考慮使用 ML-KEM 或 hybrid key establishment        |
| RSA signature                  | 考慮使用 ML-DSA 或 SLH-DSA                         |
| ECDH / DH key exchange         | 考慮使用 PQC KEM 或 hybrid key exchange            |
| ECDSA / DSA signature          | 考慮使用 ML-DSA 或 SLH-DSA                         |
| TLS configuration              | 檢查 TLS stack 是否支援 PQC 或 hybrid key exchange |
| Certificate handling           | 檢查憑證鏈與簽章演算法需求                         |
| Unknown usage                  | 需要人工進一步確認密碼學上下文                     |

系統也會提醒開發者：

- 不應該直接把一個 cryptographic primitive 換成另一個 primitive
- 許多遷移需要 protocol-level support
- 可能需要 hybrid migration strategy
- 現有 client/server 可能不支援 PQC
- 憑證格式與驗證流程可能需要調整

### 7.7 Final Security Report

最後，系統會產生完整的安全報告。報告格式包含：

- Markdown
- JSON

Markdown 報告適合人類閱讀，JSON 報告適合後續工具處理或整合。

報告內容包含：

- 掃描目標
- 掃描時間
- 總 finding 數量
- 各風險等級統計
- 每個 finding 的檔案與行號
- 使用的演算法
- 風險等級與風險分數
- 風險原因
- AI 語意分析摘要
- PQC 遷移建議
- 錯誤或略過的檔案

---

## 8. MVP 實作範圍

為了讓 final project 可以在有限時間內完成，本專案的 MVP 版本會聚焦在較明確且可實作的範圍。

### 8.1 MVP 會實作的內容

MVP 預計支援：

- 掃描本地端 Python 專案
- 偵測 Python 中常見 cryptographic API
- 萃取相關程式碼片段
- 使用 Gemini API 進行語意分析
- 進行量子風險分類
- 產生 PQC 遷移建議
- 輸出 Markdown 與 JSON 報告
- 提供 command-line interface
- 讓各模組可以獨立 unit test

### 8.2 MVP 不包含的內容

MVP 暫時不包含：

- C / C++ / Java / JavaScript / Go / Rust 等其他語言掃描
- 自動 clone GitHub repository
- CI/CD 整合
- 自動修改程式碼
- 自動產生安全 patch
- 完整 dependency vulnerability analysis
- Python 原始碼以外的 TLS runtime validation
- 完整 Semgrep 整合

這些功能會放到 future work 中。

---

## 9. 預期實作方法

### 9.1 Core Strategy：Static Analysis + AI

本專案採用 hybrid framework：

```text
Rule-Based Static Analysis + AI Semantic Auditing
```

靜態分析負責快速篩選出可能有問題的程式碼，AI 則負責判斷上下文與語意，最後由 rule-based 模組產生風險分數與遷移建議。

### 9.2 Phase 1：Rule-Based Filtering

第一階段會使用 regex 或 AST 方式偵測 Python cryptographic usage。

可能偵測的 pattern 包含：

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import dh

rsa.generate_private_key(...)
ec.generate_private_key(...)
dh.generate_parameters(...)

ssl.SSLContext(...)
ssl.create_default_context(...)
```

這一階段的目的不是做完整判斷，而是找出候選區塊。

### 9.3 Phase 2：AI Semantic Auditing

第二階段會把萃取出的程式碼片段送給 Gemini API，請模型回傳結構化 JSON。

AI 需要判斷：

- 是否是真的密碼學使用
- 是否 security-sensitive
- 使用的演算法
- 使用目的
- 是否為測試或範例
- 風險說明
- 信心分數

這可以幫助系統降低 false positive，並提升報告的可讀性。

### 9.4 Phase 3：Risk Assessment and PQC Recommendation

第三階段會根據 AI 分析結果與靜態 evidence 產生：

- 風險等級
- 風險分數
- 風險原因
- PQC 替代方向
- 開發者遷移步驟
- 相容性注意事項

---

## 10. 系統模組設計

MVP 的程式架構可以設計如下：

```text
src/
  pqc_audit/
    __init__.py
    cli.py
    config.py
    models.py
    repository.py
    static_scanner.py
    pattern_extractor.py
    gemini_analyzer.py
    risk_assessor.py
    migration_recommender.py
    report_generator.py
    pipeline.py
```

各模組職責如下：

### 10.1 `cli.py`

負責 command-line interface。

主要功能：

- 解析使用者輸入參數
- 指定掃描目標
- 指定輸出資料夾
- 選擇輸出格式
- 啟動 pipeline

範例指令：

```bash
pqc-audit --target ./example_project --output ./reports --format both
```

### 10.2 `config.py`

負責管理設定。

包含：

- target path
- output directory
- report format
- Gemini API key
- Gemini model name
- max snippet lines
- skip AI mode

### 10.3 `models.py`

定義系統內部使用的資料模型，例如：

- SourceFile
- StaticMatch
- CryptoEvidence
- SemanticAnalysis
- RiskAssessment
- MigrationRecommendation
- Finding
- AuditReport

這些資料模型讓每個模組之間可以用一致的格式交換資料。

### 10.4 `repository.py`

負責讀取目標專案。

主要功能：

- 驗證 target path 是否存在
- 搜尋 `.py` 檔案
- 忽略 `.git`、`.venv`、`__pycache__` 等資料夾
- 讀取原始碼內容
- 回傳 SourceFile list

### 10.5 `static_scanner.py`

負責靜態掃描。

主要功能：

- 偵測 Python cryptographic API
- 偵測 RSA、ECC、ECDSA、ECDH、DH 等關鍵字
- 產生 StaticMatch
- 在語法錯誤時使用 regex fallback
- 不呼叫 Gemini

### 10.6 `pattern_extractor.py`

負責將 StaticMatch 轉換成 CryptoEvidence。

主要功能：

- 根據行號萃取程式碼片段
- 將相近的 match 合併
- 推測 algorithm
- 推測 usage type
- 保留檔案與行號資訊

### 10.7 `gemini_analyzer.py`

負責 AI 語意分析。

主要功能：

- 將 evidence snippet 傳給 Gemini API
- 要求 Gemini 回傳 JSON
- 解析 Gemini 結果
- 如果 API 失敗，回傳低信心 fallback 結果
- 將 AI API 細節隔離在單一模組中

### 10.8 `risk_assessor.py`

負責量子風險評估。

主要功能：

- 根據演算法與使用情境判斷 risk level
- 產生 risk score
- 產生 risk factors
- 解釋風險原因
- 不呼叫 Gemini

### 10.9 `migration_recommender.py`

負責產生 PQC 遷移建議。

主要功能：

- 根據 algorithm 與 usage type 選擇建議
- 提供候選 PQC 演算法
- 提供 compatibility notes
- 提供 developer steps
- 對 high-risk finding 產生明確 action

### 10.10 `report_generator.py`

負責產生報告。

主要功能：

- 組合完整 AuditReport
- 輸出 Markdown
- 輸出 JSON
- 統計風險數量
- 整理 detailed findings

### 10.11 `pipeline.py`

負責串接所有模組。

執行順序：

1. 載入 Python 檔案
2. 靜態掃描
3. 萃取 evidence
4. 呼叫 Gemini 進行語意分析
5. 進行風險評估
6. 產生遷移建議
7. 組合 findings
8. 產生 Markdown / JSON 報告

---

## 11. 預期資料模型

### 11.1 SourceFile

表示一個被掃描的 Python 原始碼檔案。

欄位包含：

- path
- relative_path
- content
- line_count

### 11.2 StaticMatch

表示靜態掃描找到的一筆 cryptographic match。

欄位包含：

- file_path
- line_number
- rule_id
- matched_text
- algorithm_hint
- library_hint
- severity_hint
- line_text

### 11.3 CryptoEvidence

表示從程式碼中萃取出的密碼學 evidence。

欄位包含：

- evidence_id
- file_path
- start_line
- end_line
- snippet
- algorithm
- library
- usage_type
- source
- static_matches

### 11.4 SemanticAnalysis

表示 Gemini 對 evidence 的語意分析結果。

欄位包含：

- evidence_id
- is_real_crypto_usage
- is_security_sensitive
- algorithm
- usage_type
- is_test_or_example
- explanation
- confidence
- raw_model_output

### 11.5 RiskAssessment

表示量子風險評估結果。

欄位包含：

- evidence_id
- risk_level
- risk_score
- risk_factors
- reason

### 11.6 MigrationRecommendation

表示 PQC 遷移建議。

欄位包含：

- evidence_id
- summary
- recommended_action
- candidate_pqc_algorithms
- compatibility_notes
- developer_steps

### 11.7 Finding

表示最終報告中的一筆 finding。

欄位包含：

- evidence
- semantic_analysis
- risk_assessment
- recommendation

### 11.8 AuditReport

表示完整稽核報告。

欄位包含：

- target_path
- generated_at
- summary
- findings
- errors

---

## 12. 範例輸入與輸出

### 12.1 範例輸入程式碼

```python
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
```

### 12.2 Static Scanner 結果

```json
{
  "rule_id": "python-rsa-generate-private-key",
  "algorithm_hint": "RSA",
  "library_hint": "cryptography",
  "line_number": 3
}
```

### 12.3 Pattern Extractor 結果

```json
{
  "algorithm": "RSA",
  "usage_type": "key_generation",
  "start_line": 1,
  "end_line": 6
}
```

### 12.4 AI Semantic Analysis 結果

```json
{
  "is_real_crypto_usage": true,
  "is_security_sensitive": true,
  "algorithm": "RSA",
  "usage_type": "key_generation",
  "is_test_or_example": false,
  "confidence": 0.91
}
```

### 12.5 Quantum Risk Assessment 結果

```json
{
  "risk_level": "quantum_vulnerable",
  "risk_score": 95,
  "risk_factors": ["RSA", "key_generation"],
  "reason": "RSA relies on integer factorization, which is vulnerable to Shor's Algorithm on sufficiently powerful quantum computers."
}
```

### 12.6 PQC Migration Recommendation 結果

```json
{
  "summary": "RSA key generation was detected.",
  "recommended_action": "Review the protocol using this key and consider migration to a PQC or hybrid design.",
  "candidate_pqc_algorithms": ["ML-KEM"],
  "compatibility_notes": [
    "Direct primitive replacement may be unsafe.",
    "Protocol-level support may be required."
  ],
  "developer_steps": [
    "Identify where the generated key is used.",
    "Determine whether the key is used for encryption, signing, authentication, or key exchange.",
    "Select a PQC migration strategy based on the actual protocol role."
  ]
}
```

---

## 13. 預期成果

本專案預期產生以下成果。

### 13.1 自動偵測傳統密碼學使用

系統可以自動找出大型 Python codebase 中可能使用傳統密碼演算法的位置，例如：

- RSA
- ECC
- ECDSA
- ECDH
- Diffie-Hellman
- DSA
- TLS 相關設定

### 13.2 量子風險辨識

系統可以針對每個 finding 判斷：

- 使用的演算法
- 使用位置
- 是否為 security-sensitive usage
- 是否可能受到量子攻擊影響
- 風險等級與風險分數

### 13.3 可行的 PQC 遷移建議

系統會針對不同用途產生建議，例如：

- RSA encryption / key transport 可考慮 ML-KEM 或 hybrid key establishment
- RSA signature 可考慮 ML-DSA 或 SLH-DSA
- ECDH / DH key exchange 可考慮 PQC KEM 或 hybrid key exchange
- ECDSA / DSA signature 可考慮 PQC signature
- TLS configuration 需要檢查 TLS stack 是否支援 PQC 或 hybrid mode

### 13.4 降低人工稽核成本

透過自動化 pipeline，開發者不需要手動閱讀整個 repository，而是可以優先檢查系統標示出的高風險程式碼區塊。

---

## 14. 測試策略

為了確保系統可靠，MVP 會設計 unit tests。

測試重點包含：

- Repository loading 是否能正確找出 `.py` 檔案
- Static scanner 是否能偵測 RSA、ECC、DH、TLS 等 pattern
- Pattern extractor 是否能正確產生 snippet
- Gemini analyzer 是否能解析 JSON 回應
- Gemini API 失敗時是否能 fallback
- Risk assessor 是否能正確分類風險
- Migration recommender 是否能產生正確建議
- Report generator 是否能產生合法 Markdown 與 JSON
- Pipeline 是否能按照正確順序執行
- `skip_ai` 模式是否能在不呼叫 Gemini 的情況下執行

建議測試指令：

```bash
uv run pytest
```

---

## 15. 錯誤處理策略

系統需要區分 fatal error 與 recoverable error。

### 15.1 Fatal Error

以下錯誤會讓系統停止執行：

- target path 不存在
- target path 不是資料夾
- output directory 無法建立
- AI analysis 啟用時缺少 Gemini API key

### 15.2 Recoverable Error

以下錯誤不應該停止整個 scan，而是記錄在 final report 中：

- 某個 source file 無法讀取
- 某個 Python 檔案有 syntax error
- Gemini 對某個 evidence 分析失敗
- Gemini 回傳 malformed JSON
- 某個 evidence 無法產生 recommendation

這樣可以避免因為單一檔案或單一 API 錯誤導致整個專案掃描失敗。

---

## 16. 預期輸出檔案

若使用：

```bash
pqc-audit --target ./example_project --output ./reports --format both
```

系統會產生：

```text
./reports/security-report.md
./reports/security-report.json
```

其中：

- `security-report.md`：給開發者或報告使用的人類可讀版本
- `security-report.json`：給工具整合、後處理、CI/CD 或資料分析使用的結構化版本

---

## 17. Future Work

### 17.1 支援更多程式語言

未來可以擴充支援：

- C / C++
- Java
- JavaScript / TypeScript
- Go
- Rust
- Shell script
- YAML / configuration files

如此可以分析更多真實世界的專案。

### 17.2 支援更多密碼學 library

未來可以加入更多 library 的規則，例如：

- OpenSSL
- BoringSSL
- LibreSSL
- Java JCA
- Node.js crypto
- WebCrypto API
- Go crypto package
- Rust ring / rustls

### 17.3 CI/CD 整合

未來可以將工具整合到 CI/CD pipeline，例如：

- GitHub Actions
- GitLab CI
- Jenkins
- Pre-commit hook
- Pull request security check

這樣可以在程式碼 merge 前自動偵測潛在的量子不安全密碼學使用。

### 17.4 自動安全重構

未來可以進一步讓 AI 產生：

- patch suggestion
- refactoring template
- PQC migration checklist
- secure coding recommendation
- protocol-level migration guidance

### 17.5 大規模 repository 評估

未來可以在大型 open-source repositories 或 enterprise-scale repositories 上進行測試，評估：

- detection accuracy
- false positive rate
- false negative rate
- execution time
- AI API cost
- recommendation usefulness
- scalability

---

## 18. 專案結論

本 final project 提出一個 **AI 輔助密碼學稽核與後量子密碼遷移框架**。它的核心想法是結合靜態分析的速度與 AI 語意分析的理解能力，協助開發者在大型 codebase 中找出可能受到量子運算威脅的傳統密碼學使用。

整體 pipeline 從 source code repository 開始，經過 static scanner、cryptographic pattern extraction、AI semantic analysis、quantum risk assessment、PQC migration suggestion，最後產生 final security report。

這個系統的價值在於：

- 幫助開發者快速定位傳統密碼學使用
- 判斷哪些使用可能具有量子風險
- 產生清楚且可行的 PQC 遷移建議
- 降低人工稽核成本
- 為未來的 post-quantum migration 做準備

在 MVP 版本中，系統會優先支援 Python 專案，並使用 Gemini API 進行 AI 語意分析。未來則可以擴充到更多語言、更多 library、CI/CD 整合與自動安全重構。
