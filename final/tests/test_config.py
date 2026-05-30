from pathlib import Path

import pytest

from pqc_audit.config import (
    DEFAULT_GEMINI_MODEL,
    AppConfig,
    ConfigError,
    build_config,
    load_dotenv,
)


def test_config_defaults(tmp_path: Path) -> None:
    config = AppConfig(
        target_path=tmp_path,
        output_dir=tmp_path / "reports",
        gemini_api_key="key",
    )

    assert config.report_format == "both"
    assert config.gemini_model == DEFAULT_GEMINI_MODEL
    assert config.max_snippet_lines == 40


def test_build_config_loads_environment_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "from-env")

    config = build_config(tmp_path, tmp_path / "reports")

    assert config.gemini_api_key == "from-env"


def test_build_config_loads_dotenv_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("GEMINI_API_KEY=from-dotenv\n", encoding="utf-8")

    config = build_config(tmp_path, tmp_path / "reports", env_file=env_file)

    assert config.gemini_api_key == "from-dotenv"


def test_environment_key_overrides_dotenv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "from-env")
    env_file = tmp_path / ".env"
    env_file.write_text("GEMINI_API_KEY=from-dotenv\n", encoding="utf-8")

    config = build_config(tmp_path, tmp_path / "reports", env_file=env_file)

    assert config.gemini_api_key == "from-env"


def test_load_dotenv_ignores_comments_and_strips_quotes(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# comment\nGEMINI_API_KEY='quoted-key'\nEMPTY_LINE=\n",
        encoding="utf-8",
    )

    values = load_dotenv(env_file)

    assert values["GEMINI_API_KEY"] == "quoted-key"
    assert values["EMPTY_LINE"] == ""


def test_missing_gemini_key_fails_when_ai_enabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    with pytest.raises(ConfigError):
        build_config(
            tmp_path,
            tmp_path / "reports",
            skip_ai=False,
            env_file=tmp_path / "missing.env",
        )


def test_missing_gemini_key_allowed_when_skip_ai(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    config = build_config(
        tmp_path,
        tmp_path / "reports",
        skip_ai=True,
        env_file=tmp_path / "missing.env",
    )

    assert config.gemini_api_key is None
    assert config.skip_ai is True


def test_invalid_target_path_fails(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        AppConfig(tmp_path / "missing", tmp_path, "both", "key").validate()


def test_target_path_must_be_directory(tmp_path: Path) -> None:
    file_path = tmp_path / "file.py"
    file_path.write_text("", encoding="utf-8")

    with pytest.raises(ConfigError):
        AppConfig(file_path, tmp_path, "both", "key").validate()


def test_invalid_report_format_fails(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        AppConfig(tmp_path, tmp_path, "xml", "key").validate()  # type: ignore[arg-type]


def test_custom_gemini_model(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "key")

    config = build_config(
        tmp_path,
        tmp_path / "reports",
        gemini_model="gemini-2.0-flash",
    )

    assert config.gemini_model == "gemini-2.0-flash"
