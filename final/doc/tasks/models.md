# models.py 任務

## 目標

建立系統共用資料模型，讓各 module 之間用一致且可測試的資料格式交換資料。

## 輸入依據

- `doc/final_project_proposal.md`
- `doc/detailed-design.md`

## 輸出

- `src/pqc_audit/models.py`
- `tests/test_models.py`

## 最小可執行任務

- [ ] 建立 `src/pqc_audit/` package 與 `__init__.py`
- [ ] 在 `models.py` 定義 `SourceFile`
- [ ] 在 `models.py` 定義 `StaticMatch`
- [ ] 在 `models.py` 定義 `CryptoEvidence`
- [ ] 在 `models.py` 定義 `SemanticAnalysis`
- [ ] 在 `models.py` 定義 `RiskAssessment`
- [ ] 在 `models.py` 定義 `MigrationRecommendation`
- [ ] 在 `models.py` 定義 `Finding`
- [ ] 在 `models.py` 定義 `AuditReport`
- [ ] 為 risk level 定義固定允許值
- [ ] 為 usage type 定義固定允許值
- [ ] 加入必要型別標註，避免 module 之間傳遞不明資料結構
- [ ] 撰寫測試確認每個 model 可以正確建立實例
- [ ] 撰寫測試確認 list 與 nested model 欄位可正常使用
- [ ] 執行 `uv run pytest tests/test_models.py`

## 驗收條件

- [ ] 所有設計文件列出的資料模型都已存在
- [ ] 每個 model 的欄位名稱與設計文件一致
- [ ] 測試不需要 Gemini API 或網路
- [ ] `uv run pytest tests/test_models.py` 通過

## 不做的事

- [ ] 不實作掃描邏輯
- [ ] 不實作 Gemini API 呼叫
- [ ] 不產生報告檔案
