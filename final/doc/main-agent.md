# Main Agent Execution Plan

## 1. Overall Goal

本專案目前目標是實作多語言 MVP：掃描本地專案中的 Python、JavaScript/TypeScript、Java、C/C++ 傳統密碼學使用，透過 Gemini API 做語意分析，評估量子風險，產生 PQC 遷移建議，並輸出 Markdown 與 JSON 報告。

## 2. Main Agent Responsibility

Main agent 只負責協調與整合，不應該一開始就直接修改所有檔案。

Main agent 負責：

- 閱讀 project-level 文件
- 分派 subagent
- 收集 subagent report
- 決定實作順序
- 控制 cross-module interface
- 執行測試與整合
- 更新 `doc/tasks/progress.md`

Main agent 不負責：

- 同時實作所有 module
- 讓 subagent 自行跨 module 修改
- 把 `progress.md` 寫成開發日記
- 在 Phase A 直接修改 source code

## 3. Context Control Policy

### Main Agent 可讀文件

Main agent 可讀：

- `/home/apollo/.codex/AGENTS.md`
- `doc/final_project_proposal.md`
- `doc/detailed-design.md`
- `doc/tasks/progress.md`
- `doc/tasks/<module>.md`
- 當前 batch 需要整合的 source/test files

注意：使用者若提到 `doc/proposal.md`，在此 repo 中對應為 `doc/final_project_proposal.md`。

### Subagent 可讀文件

每個 subagent 原則上只可讀：

- `/home/apollo/.codex/AGENTS.md`
- `doc/tasks/<own_module>.md`
- 自己負責的 source file
- 自己負責的 test file
- 必要時讀 `src/pqc_audit/models.py`，但只能用來理解共用資料模型

### Subagent 不應該讀的文件

subagent 不應該讀：

- 其他 module 的 `doc/tasks/*.md`
- 與自己 module 無關的 source files
- 與自己 module 無關的 tests
- 整份 `doc/detailed-design.md`，除非 main agent 明確要求
- 整份 `doc/final_project_proposal.md`，除非 main agent 明確要求

### 要求讀取其他 module 文件的條件

subagent 只有在以下情況可以向 main agent 要求額外讀取權限：

- 發現 interface 不一致
- 需要確認共用 model 欄位
- 測試失敗來自其他 module 行為
- 自己的任務明確依賴另一個 module 的輸出格式

subagent 必須先回報：

- 想讀哪個檔案
- 為什麼需要讀
- 不讀會阻塞哪個任務

未經 main agent 同意，不可自行讀取或修改其他 module 文件。

### Repo 掃描限制

- 不可以掃描整個 repo，除非有明確理由。
- 優先使用精準檔案路徑讀取。
- 搜尋時優先限制在 `doc/tasks/`、`src/pqc_audit/`、`tests/`。
- 不可以讀 `.venv/`、cache、generated files、large binary files。
- 不可以讀 `__pycache__/`、`.pytest_cache/`、`.mypy_cache/`、`dist/`、`build/`。

## 4. Subagent Assignment Table

| Subagent | Read-only files | Editable files | Related tests | Notes |
| --- | --- | --- | --- | --- |
| models-agent | `/home/apollo/.codex/AGENTS.md`, `doc/tasks/models.md` | `src/pqc_audit/__init__.py`, `src/pqc_audit/models.py` | `tests/test_models.py` | 建立共用資料模型；跨 module interface 需由 main agent 確認。 |
| config-agent | `/home/apollo/.codex/AGENTS.md`, `doc/tasks/config.md`, `src/pqc_audit/models.py` | `src/pqc_audit/config.py` | `tests/test_config.py` | 不解析 CLI；只處理設定與驗證。 |
| repository-agent | `/home/apollo/.codex/AGENTS.md`, `doc/tasks/repository.md`, `src/pqc_audit/models.py` | `src/pqc_audit/repository.py` | `tests/test_repository.py` | 不掃描 crypto pattern；只載入 Python files。 |
| static-scanner-agent | `/home/apollo/.codex/AGENTS.md`, `doc/tasks/static_scanner.md`, `src/pqc_audit/models.py` | `src/pqc_audit/static_scanner.py` | `tests/test_static_scanner.py` | 不產生 evidence、不評分、不呼叫 Gemini。 |
| pattern-extractor-agent | `/home/apollo/.codex/AGENTS.md`, `doc/tasks/pattern_extractor.md`, `src/pqc_audit/models.py` | `src/pqc_audit/pattern_extractor.py` | `tests/test_pattern_extractor.py` | 只把 match 轉 evidence。 |
| risk-assessor-agent | `/home/apollo/.codex/AGENTS.md`, `doc/tasks/risk_assessor.md`, `src/pqc_audit/models.py` | `src/pqc_audit/risk_assessor.py` | `tests/test_risk_assessor.py` | Rule-based；不可呼叫 Gemini。 |
| migration-recommender-agent | `/home/apollo/.codex/AGENTS.md`, `doc/tasks/migration_recommender.md`, `src/pqc_audit/models.py` | `src/pqc_audit/migration_recommender.py` | `tests/test_migration_recommender.py` | Rule-based；不可產生 patch。 |
| report-generator-agent | `/home/apollo/.codex/AGENTS.md`, `doc/tasks/report_generator.md`, `src/pqc_audit/models.py` | `src/pqc_audit/report_generator.py` | `tests/test_report_generator.py` | 只負責 Markdown/JSON report formatting。 |
| gemini-analyzer-agent | `/home/apollo/.codex/AGENTS.md`, `doc/tasks/gemini_analyzer.md`, `src/pqc_audit/models.py`, `src/pqc_audit/config.py` | `src/pqc_audit/gemini_analyzer.py` | `tests/test_gemini_analyzer.py` | Gemini 細節只放此 module；測試必須 mock network。 |
| pipeline-agent | `/home/apollo/.codex/AGENTS.md`, `doc/tasks/pipeline.md`, current implemented module interfaces | `src/pqc_audit/pipeline.py` | `tests/test_pipeline.py` | 高耦合整合層；跨 module mismatch 必須回報 main agent。 |
| cli-agent | `/home/apollo/.codex/AGENTS.md`, `doc/tasks/cli.md`, `src/pqc_audit/config.py`, `src/pqc_audit/pipeline.py` | `src/pqc_audit/cli.py`, `pyproject.toml` | `tests/test_cli.py` | 只做 CLI wiring；修改 `pyproject.toml` 前由 main agent 確認。 |

原則：每個 subagent 只能修改自己的 module source file 與 related test。若需要跨 module 修改，必須先回報 main agent，不可以直接改。

## 5. Phase A: Read-only Audit

第一階段只做 read-only audit。所有 subagent 只能閱讀，不可以修改檔案。

Main agent 建立 subagents 時，應明確指定：

- 只能讀 assignment table 中列出的 read-only files
- 不可以修改任何檔案
- 不可以執行 implementation
- 不可以掃描整個 repo

每個 subagent 必須回報：

1. 讀了哪些檔案
2. 目前 implementation status
3. 已完成的項目
4. 尚未完成的項目
5. 可能需要跨 module 協調的地方
6. 建議的最小修改範圍
7. 風險等級：low / medium / high

Main agent 收到所有 report 後，才決定 Phase B 的實作 batch 是否需要調整。

## 6. Phase B: Implementation Batches

不要讓所有 subagent 一次同時修改 code。每個 batch 完成後，main agent 要先跑對應測試並更新 `doc/tasks/progress.md`。

### Batch 1：基礎 interface module

Modules:

- `models.py`
- `config.py`

原因：

- `models.py` 是所有 module 的共用資料格式。
- `config.py` 是 CLI、Gemini、pipeline 的共用設定來源。

允許修改：

- `src/pqc_audit/__init__.py`
- `src/pqc_audit/models.py`
- `src/pqc_audit/config.py`
- `tests/test_models.py`
- `tests/test_config.py`

測試：

- `uv run pytest tests/test_models.py tests/test_config.py`

progress 更新：

- 更新 `models.py` 與 `config.py` module status
- 勾選已完成 checklist
- 記錄 failing tests、blockers、next action

### Batch 2：低耦合資料取得與靜態掃描

Modules:

- `repository.py`
- `static_scanner.py`

原因：

- 兩者依賴 `models.py`，但彼此可用獨立 fixture 測試。
- 不需要 Gemini、不需要 report、不需要 pipeline。

允許修改：

- `src/pqc_audit/repository.py`
- `src/pqc_audit/static_scanner.py`
- `tests/test_repository.py`
- `tests/test_static_scanner.py`

測試：

- `uv run pytest tests/test_repository.py tests/test_static_scanner.py`

progress 更新：

- 更新 `repository.py` 與 `static_scanner.py`
- 記錄是否有 scanner rule 或 ignored directory blocker

### Batch 3：核心 rule-based logic

Modules:

- `pattern_extractor.py`
- `risk_assessor.py`
- `migration_recommender.py`
- `report_generator.py`

原因：

- 這批主要依賴 models 與前面定義的資料形狀。
- 都可以用 unit test 與 fake data 驗證，不需要 Gemini。

允許修改：

- `src/pqc_audit/pattern_extractor.py`
- `src/pqc_audit/risk_assessor.py`
- `src/pqc_audit/migration_recommender.py`
- `src/pqc_audit/report_generator.py`
- `tests/test_pattern_extractor.py`
- `tests/test_risk_assessor.py`
- `tests/test_migration_recommender.py`
- `tests/test_report_generator.py`

測試：

- `uv run pytest tests/test_pattern_extractor.py tests/test_risk_assessor.py tests/test_migration_recommender.py tests/test_report_generator.py`

progress 更新：

- 更新四個 module status
- 只記錄完成項目、失敗測試、blockers、next action

### Batch 4：外部 API 邊界

Modules:

- `gemini_analyzer.py`

原因：

- Gemini 是外部 API 邊界，應在 rule-based modules 穩定後實作。
- 測試必須 mock Gemini client，不可依賴真實 API key 或網路。

允許修改：

- `src/pqc_audit/gemini_analyzer.py`
- `tests/test_gemini_analyzer.py`

測試：

- `uv run pytest tests/test_gemini_analyzer.py`

progress 更新：

- 更新 `gemini_analyzer.py`
- 記錄 mock coverage、fallback 行為、API key blocker

### Batch 5：高耦合整合層

Modules:

- `pipeline.py`
- `cli.py`

原因：

- `pipeline.py` 需要整合所有 module。
- `cli.py` 需要連接 config 與 pipeline，並可能修改 `pyproject.toml` entry point。

允許修改：

- `src/pqc_audit/pipeline.py`
- `src/pqc_audit/cli.py`
- `tests/test_pipeline.py`
- `tests/test_cli.py`
- `pyproject.toml`

測試：

- `uv run pytest tests/test_pipeline.py tests/test_cli.py`

progress 更新：

- 更新 `pipeline.py` 與 `cli.py`
- 記錄 entry point、skip_ai、report format、整合測試狀態

### Batch 6：Final Integration

Modules:

- 全部 module，但只允許修正整合錯誤。

原因：

- 所有 module 完成後才能驗證完整 import、test suite 與 CLI path。

允許修改：

- 只允許修改造成測試失敗的最小檔案集合。
- 若需跨 module 修改，main agent 必須明確記錄原因。

測試：

- `uv run pytest`
- 必要時加上 CLI smoke test，但不得呼叫真實 Gemini API，優先使用 `--skip-ai`。

progress 更新：

- 更新整體驗收 checklist
- 記錄 failing tests、blockers、next action

## 7. Phase C: Testing and Integration

測試流程：

1. 每個 subagent 完成 module 後跑 module-level tests。
2. 每個 batch 完成後跑 batch tests。
3. Batch 6 跑 full test command。

Full test command:

```bash
uv run pytest
```

如果測試失敗，main agent 應分派 debug subagent。

debug subagent 可讀：

- 失敗測試檔案
- pytest failure output
- 對應 module source file
- 對應 `doc/tasks/<module>.md`
- 必要時讀 `src/pqc_audit/models.py`

debug subagent 可改：

- 失敗測試對應的 module source file
- 失敗測試檔案

debug subagent 不可改：

- 無關 module
- `doc/tasks/progress.md`
- project-level 設計文件
- dependency 或 lock file，除非 main agent 明確批准

debug subagent 回報格式：

- 失敗原因
- 修改檔案
- 修改摘要
- 重跑測試結果
- 是否需要 main agent 處理跨 module 問題

## 8. Phase D: Progress Update

每次完成一個 batch 後，main agent 必須更新 `doc/tasks/progress.md`。

`progress.md` 只記錄：

- module status
- completed checklist
- failing tests
- blockers
- next action

`progress.md` 不應包含：

- 長篇開發日記
- 大量 pytest output
- 大段程式碼
- 重複貼上 task 文件內容

建議 status 值：

- `not_started`
- `audit_done`
- `in_progress`
- `implemented`
- `tested`
- `blocked`

## 9. Final Main Agent Prompt

可直接複製給 Codex main agent：

```text
請依照 `doc/main-agent.md` 執行 Phase A read-only audit。

限制：
- 不要實作程式。
- 不要修改任何檔案。
- 不要掃描整個 repo。
- 不要讀 `.venv/`、cache、generated files、large binary files。
- main agent 只讀 `doc/main-agent.md`、`doc/tasks/progress.md`，以及必要的 project-level 文件。
- 每個 subagent 原則上只讀自己的 `doc/tasks/<module>.md`、`/home/apollo/.codex/AGENTS.md`，以及 assignment table 允許的 read-only files。

請建立以下 read-only audit subagents：
- models-agent
- config-agent
- repository-agent
- static-scanner-agent
- pattern-extractor-agent
- risk-assessor-agent
- migration-recommender-agent
- report-generator-agent
- gemini-analyzer-agent
- pipeline-agent
- cli-agent

每個 subagent 必須回報：
1. 它讀了哪些檔案
2. 目前 implementation status
3. 已完成的項目
4. 尚未完成的項目
5. 可能需要跨 module 協調的地方
6. 建議的最小修改範圍
7. 風險等級：low / medium / high

完成後，main agent 彙整所有 audit reports，提出 Phase B batch execution 建議，但不要開始 implementation。
```
