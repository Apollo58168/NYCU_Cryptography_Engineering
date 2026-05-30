# 任務進度

## Module Status

| Module | Status | Tests |
| --- | --- | --- |
| `models.py` | tested | `uv run pytest tests/test_models.py` |
| `config.py` | tested | `uv run pytest tests/test_config.py` |
| `repository.py` | tested | `uv run pytest tests/test_repository.py` |
| `static_scanner.py` | tested | `uv run pytest tests/test_static_scanner.py` |
| `pattern_extractor.py` | tested | `uv run pytest tests/test_pattern_extractor.py` |
| `gemini_analyzer.py` | tested | `uv run pytest tests/test_gemini_analyzer.py` |
| `risk_assessor.py` | tested | `uv run pytest tests/test_risk_assessor.py` |
| `migration_recommender.py` | tested | `uv run pytest tests/test_migration_recommender.py` |
| `report_generator.py` | tested | `uv run pytest tests/test_report_generator.py` |
| `pipeline.py` | tested | `uv run pytest tests/test_pipeline.py` |
| `cli.py` | tested | `uv run pytest tests/test_cli.py` |

## Completed Checklist

- [x] 建立 `src/pqc_audit/` package
- [x] 建立共用資料模型
- [x] 建立 runtime config 與 Gemini API key 驗證
- [x] 支援本地 Python 專案載入
- [x] 支援 Python cryptographic static scanning
- [x] 支援 `StaticMatch` 到 `CryptoEvidence` 萃取
- [x] 支援 Gemini analyzer 並以 mock 測試 API 邊界
- [x] 支援 `skip_ai` static fallback
- [x] 支援 quantum risk assessment
- [x] 支援 PQC migration recommendation
- [x] 支援 Markdown report
- [x] 支援 JSON report
- [x] 支援 pipeline orchestration
- [x] 支援 `pqc-audit` CLI entry point
- [x] 完整測試通過
- [x] CLI smoke test 通過

## Failing Tests

- None

## Blockers

- None

## Next Action

- 可進行人工 review 或使用 `pqc-audit --target <python_project> --output <report_dir> --format both --skip-ai` 掃描目標專案。
- 若要使用 Gemini 模式，需設定 `GEMINI_API_KEY` 並移除 `--skip-ai`。

