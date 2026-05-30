from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from pqc_audit.models import SourceFile


IGNORED_DIRECTORIES: tuple[str, ...] = (
    ".git",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "node_modules",
    "dist",
    "build",
)

SUPPORTED_SOURCE_EXTENSIONS: tuple[str, ...] = (
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
)


class RepositoryError(ValueError):
    """Raised when the target repository path is invalid."""


@dataclass(slots=True)
class RepositoryScanResult:
    source_files: list[SourceFile]
    errors: list[str]


def scan_repository(target_path: Path) -> RepositoryScanResult:
    root = target_path.resolve()
    validate_target_path(root)

    source_files: list[SourceFile] = []
    errors: list[str] = []

    for current_root, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name not in IGNORED_DIRECTORIES)

        for filename in sorted(filenames):
            if Path(filename).suffix not in SUPPORTED_SOURCE_EXTENSIONS:
                continue

            file_path = Path(current_root) / filename
            try:
                source_files.append(read_source_file(file_path, root))
            except OSError as exc:
                relative_path = file_path.relative_to(root).as_posix()
                errors.append(f"Failed to read {relative_path}: {exc}")
            except UnicodeError as exc:
                relative_path = file_path.relative_to(root).as_posix()
                errors.append(f"Failed to read {relative_path}: {exc}")

    return RepositoryScanResult(source_files, errors)


def load_source_files(target_path: Path) -> list[SourceFile]:
    return scan_repository(target_path).source_files


def validate_target_path(target_path: Path) -> None:
    if not target_path.exists():
        raise RepositoryError(f"Target path does not exist: {target_path}")
    if not target_path.is_dir():
        raise RepositoryError(f"Target path is not a directory: {target_path}")


def read_source_file(path: Path, root: Path) -> SourceFile:
    content = path.read_text(encoding="utf-8")
    return SourceFile(
        path=path,
        relative_path=path.relative_to(root).as_posix(),
        content=content,
        line_count=len(content.splitlines()),
    )
