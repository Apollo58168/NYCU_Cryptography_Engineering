from pathlib import Path

import pytest

from pqc_audit.repository import (
    IGNORED_DIRECTORIES,
    RepositoryError,
    load_source_files,
    scan_repository,
)


def test_scan_repository_returns_only_python_files(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# docs\n", encoding="utf-8")

    result = scan_repository(tmp_path)

    assert [source.relative_path for source in result.source_files] == ["app.py"]
    assert result.errors == []


def test_scan_repository_ignores_unrelated_directories(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('ok')\n", encoding="utf-8")
    for directory_name in IGNORED_DIRECTORIES:
        ignored_dir = tmp_path / directory_name
        ignored_dir.mkdir()
        (ignored_dir / "ignored.py").write_text("print('ignored')\n", encoding="utf-8")

    result = scan_repository(tmp_path)

    assert [source.relative_path for source in result.source_files] == ["main.py"]


def test_scan_repository_builds_source_file_metadata(tmp_path: Path) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    source_path = package_dir / "module.py"
    source_path.write_text("first\nsecond\n", encoding="utf-8")

    result = scan_repository(tmp_path)

    assert len(result.source_files) == 1
    source = result.source_files[0]
    assert source.path == source_path
    assert source.relative_path == "pkg/module.py"
    assert source.content == "first\nsecond\n"
    assert source.line_count == 2


def test_missing_target_path_fails(tmp_path: Path) -> None:
    with pytest.raises(RepositoryError):
        scan_repository(tmp_path / "missing")


def test_target_path_must_be_directory(tmp_path: Path) -> None:
    target_file = tmp_path / "file.py"
    target_file.write_text("", encoding="utf-8")

    with pytest.raises(RepositoryError):
        scan_repository(target_file)


def test_single_file_read_failure_is_recoverable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    good_path = tmp_path / "good.py"
    bad_path = tmp_path / "bad.py"
    good_path.write_text("print('good')\n", encoding="utf-8")
    bad_path.write_text("print('bad')\n", encoding="utf-8")

    original_read_text = Path.read_text

    def fake_read_text(path: Path, *args: object, **kwargs: object) -> str:
        if path == bad_path:
            raise OSError("permission denied")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fake_read_text)

    result = scan_repository(tmp_path)

    assert [source.relative_path for source in result.source_files] == ["good.py"]
    assert result.errors == ["Failed to read bad.py: permission denied"]


def test_load_source_files_returns_source_file_list(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")

    source_files = load_source_files(tmp_path)

    assert len(source_files) == 1
    assert source_files[0].relative_path == "app.py"
