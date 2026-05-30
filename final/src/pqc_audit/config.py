from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from pqc_audit.models import REPORT_FORMATS, ReportFormat


DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
DEFAULT_MAX_SNIPPET_LINES = 40
DEFAULT_ENV_FILE = Path(".env")


class ConfigError(ValueError):
    """Raised when runtime configuration is invalid."""


@dataclass(slots=True)
class AppConfig:
    target_path: Path
    output_dir: Path
    report_format: ReportFormat = "both"
    gemini_api_key: str | None = None
    gemini_model: str = DEFAULT_GEMINI_MODEL
    max_snippet_lines: int = DEFAULT_MAX_SNIPPET_LINES
    skip_ai: bool = False

    def validate(self) -> None:
        if not self.target_path.exists():
            raise ConfigError(f"Target path does not exist: {self.target_path}")
        if not self.target_path.is_dir():
            raise ConfigError(f"Target path is not a directory: {self.target_path}")
        if self.report_format not in REPORT_FORMATS:
            raise ConfigError(f"Invalid report format: {self.report_format}")
        if self.max_snippet_lines <= 0:
            raise ConfigError("max_snippet_lines must be positive")
        if not self.skip_ai and not self.gemini_api_key:
            raise ConfigError("GEMINI_API_KEY is required when AI analysis is enabled")


def load_dotenv(path: Path = DEFAULT_ENV_FILE) -> dict[str, str]:
    if not path.exists():
        return {}

    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def load_gemini_api_key(env_file: Path = DEFAULT_ENV_FILE) -> str | None:
    return os.environ.get("GEMINI_API_KEY") or load_dotenv(env_file).get("GEMINI_API_KEY")


def build_config(
    target_path: Path,
    output_dir: Path,
    report_format: str = "both",
    max_snippet_lines: int = DEFAULT_MAX_SNIPPET_LINES,
    skip_ai: bool = False,
    gemini_model: str = DEFAULT_GEMINI_MODEL,
    env_file: Path = DEFAULT_ENV_FILE,
) -> AppConfig:
    config = AppConfig(
        target_path=target_path,
        output_dir=output_dir,
        report_format=report_format,  # type: ignore[arg-type]
        gemini_api_key=load_gemini_api_key(env_file),
        gemini_model=gemini_model,
        max_snippet_lines=max_snippet_lines,
        skip_ai=skip_ai,
    )
    config.validate()
    return config
