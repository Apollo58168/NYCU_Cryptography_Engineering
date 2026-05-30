from pathlib import Path

import pytest

from pqc_audit import cli


class FakePipeline:
    received_config = None

    def run(self, config):
        FakePipeline.received_config = config
        return type("Report", (), {"summary": {"total_findings": 0}})()


def test_parser_rejects_invalid_report_format() -> None:
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(
            ["--target", ".", "--output", "reports", "--format", "xml"]
        )


def test_cli_passes_config_to_pipeline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "AuditPipeline", FakePipeline)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    exit_code = cli.main(
        [
            "--target",
            str(tmp_path),
            "--output",
            str(tmp_path / "reports"),
            "--format",
            "json",
            "--gemini-model",
            "gemini-2.0-flash",
            "--skip-ai",
        ]
    )

    assert exit_code == 0
    assert FakePipeline.received_config.target_path == tmp_path
    assert FakePipeline.received_config.report_format == "json"
    assert FakePipeline.received_config.gemini_model == "gemini-2.0-flash"
    assert FakePipeline.received_config.skip_ai is True


def test_cli_returns_error_for_invalid_target(tmp_path: Path) -> None:
    exit_code = cli.main(
        [
            "--target",
            str(tmp_path / "missing"),
            "--output",
            str(tmp_path / "reports"),
            "--skip-ai",
        ]
    )

    assert exit_code == 1
