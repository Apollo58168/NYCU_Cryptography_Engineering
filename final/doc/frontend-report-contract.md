# Frontend Report Contract

這份文件說明前端接 `/api/scan` 或讀 `security-report.json` 時，應該如何使用後端新增的 report 欄位。

## 1. Summary Fields

`summary` 目前包含：

- `total_findings`
- `quantum_vulnerable`
- `partially_vulnerable`
- `quantum_safe`
- `unknown`
- `category_counts`
- `confidence_counts`
- `evidence_type_counts`
- `usage_type_counts`
- `algorithm_counts`

前端 dashboard 建議顯示：

- `category_counts.vulnerability`
- `category_counts.needs_review`
- `category_counts.quantum_safe`
- `category_counts.low_confidence`

不要只顯示 `total_findings`，因為 safe crypto 與 low-confidence finding 會讓總數變大，但不代表都是漏洞。

## 2. Finding Category

每個 finding 的 `risk_assessment.finding_category` 會是：

- `vulnerability`
- `needs_review`
- `quantum_safe`
- `low_confidence`

前端左側列表建議做四個 filter tab：

- Vulnerable
- Needs Review
- Quantum Safe
- Low Confidence

預設顯示 `vulnerability`，避免 import-only、comment-only、test/example 造成畫面太吵。

## 3. Sorting

每個 finding 的 `risk_assessment.display_priority` 是前端排序用欄位。

建議排序：

```text
display_priority asc
risk_score desc
file_path asc
start_line asc
```

不要只用 `risk_score` 排序，因為 low-confidence finding 仍可能有中高分。

## 4. Finding Card Fields

左側 finding card 建議顯示：

- `evidence.algorithm`
- `evidence.usage_type`
- `evidence.library`
- `risk_assessment.risk_level`
- `risk_assessment.risk_score`
- `risk_assessment.finding_category`
- `risk_assessment.confidence`
- `evidence.evidence_type`
- `evidence.source_kind`
- `evidence.file_path`

範例：

```text
RSA                       score 70
quantum_vulnerable        low_confidence
import / code             cryptography
tests/x509/test_x509_ext.py
```

## 5. Detail Panel Fields

右側 detail panel 建議新增：

- Risk Level
- Finding Category
- Confidence
- Evidence Type
- Source Kind
- Usage Type
- Library
- Risk Factors

對應欄位：

- `risk_assessment.risk_level`
- `risk_assessment.finding_category`
- `risk_assessment.confidence`
- `evidence.evidence_type`
- `evidence.source_kind`
- `evidence.usage_type`
- `evidence.library`
- `risk_assessment.risk_factors`

`risk_factors` 應該以 badge 或 list 顯示，讓使用者知道為什麼被降權或被分類。

## 6. Evidence Types

`evidence.evidence_type` 可能是：

- `api_call`
- `import`
- `config`
- `keyword`
- `comment_or_string`
- `unknown`

前端建議：

- `api_call`：高可信，正常顯示
- `config`：中可信，放 Needs Review 或依 category 顯示
- `import`：通常只是候選，預設放 Low Confidence
- `keyword`：預設放 Low Confidence
- `comment_or_string`：預設放 Low Confidence

## 7. Source Kinds

`evidence.source_kind` 可能是：

- `code`
- `comment`
- `string`
- `unknown`

如果是 `comment` 或 `string`，前端應該明顯標示為 low-confidence，不要當成主要漏洞。

## 8. New Usage Types

後端新增：

- `hashing`
- `mac`
- `symmetric_encryption`

這些通常會和 AES、SHA-2、SHA-3、HMAC 對應，風險多半是 `quantum_safe`。

前端不要把它們放在 Vulnerabilities 預設列表，應該放在 Quantum Safe tab。

## 9. Quantum-Safe Findings

AES / SHA / HMAC 類 finding 的用途是告訴使用者：

- 後端確實看到了這些 crypto usage
- 它們不是 Shor-vulnerable public-key crypto
- 不需要和 RSA/ECDSA/ECDH/DH 一樣進行 PQC migration

前端可以把 Quantum Safe 當成「coverage signal」，而不是 vulnerability。

## 10. Required Frontend Changes

前端需要做：

1. 新增 category filter tabs。
2. 預設只顯示 `finding_category === "vulnerability"`。
3. 使用 `display_priority` 排序。
4. finding card 顯示 confidence、evidence type、usage type、library。
5. detail panel 顯示 risk factors。
6. 將 `quantum_safe` findings 放到獨立 tab。
7. 將 `low_confidence` findings 放到獨立 tab。
8. 不要用 `total_findings === vulnerable count` 的假設。

