"""A path, file or lockfile that was not scanned is not a clean one.

Every way of scanning nothing has to end in a warning and, under --ci, in
exit code 2 unless --allow-unscanned is given.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from heckler import scanner as scanner_module
from heckler.cli import main
from heckler.scanner import Scanner

PLANTED = "x = 'a" + chr(0x200B) + "b'\n"

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not available")


def _root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


needs_permissions = pytest.mark.skipif(
    os.name == "nt" or _root(), reason="needs a file mode that denies reading"
)


class TestMissingPath:
    def test_missing_path_is_an_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        missing = tmp_path / "scr"
        assert main([str(missing)]) == 2
        captured = capsys.readouterr()
        assert f"Error: path not found: {missing}" in captured.err
        assert "No dangerous" not in captured.out

    def test_with_ci(self, tmp_path: Path) -> None:
        assert main(["--ci", str(tmp_path / "scr")]) == 2

    def test_allow_unscanned_does_not_excuse_it(self, tmp_path: Path) -> None:
        assert main(["--ci", "--allow-unscanned", str(tmp_path / "scr")]) == 2

    def test_one_missing_among_several_stops_the_run(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "a.py").write_text(PLANTED, encoding="utf-8")
        assert main(["--ci", str(tmp_path / "src"), str(tmp_path / "a"), str(tmp_path / "b")]) == 2
        captured = capsys.readouterr()
        assert f"path not found: {tmp_path / 'a'}, {tmp_path / 'b'}" in captured.err
        assert captured.out == ""

    def test_existing_paths_are_unaffected(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        assert main(["--ci", str(tmp_path), str(tmp_path / "a.py")]) == 0

    def test_library_records_it(self, tmp_path: Path) -> None:
        scanner = Scanner()
        assert scanner.scan_path(tmp_path / "nope") == []
        assert scanner.skipped == [(str(tmp_path / "nope"), "it does not exist")]


class TestSkippedFiles:
    @pytest.fixture
    def small_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(scanner_module, "_MAX_SCAN_FILE_SIZE", 2 * 1024 * 1024)

    @pytest.fixture
    def project(self, tmp_path: Path, small_limit: None) -> Path:
        (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "huge.js").write_bytes(PLANTED.encode() + b"/" * (2 * 1024 * 1024))
        return tmp_path

    def test_scanner_records_a_file_that_is_too_large(self, project: Path) -> None:
        scanner = Scanner()
        assert scanner.scan_path(project) == []
        assert scanner.skipped == [(str(project / "huge.js"), "it is larger than 2 MB")]

    def test_a_file_at_the_limit_is_scanned(self, tmp_path: Path, small_limit: None) -> None:
        body = PLANTED.encode()
        (tmp_path / "big.js").write_bytes(body + b"/" * (2 * 1024 * 1024 - len(body)))
        scanner = Scanner()
        assert len(scanner.scan_path(tmp_path)) == 1
        assert scanner.skipped == []

    def test_ci_fails_with_exit_code_2(
        self, project: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["--ci", str(project)]) == 2
        captured = capsys.readouterr()
        assert f"Warning: {project / 'huge.js'} was not scanned: it is larger than" in captured.err
        assert "Error: 1 item(s) could not be scanned" in captured.err
        assert "--allow-unscanned" in captured.err
        assert "No dangerous" not in captured.out

    def test_allow_unscanned_passes_but_still_warns(
        self, project: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["--ci", "--allow-unscanned", str(project)]) == 0
        captured = capsys.readouterr()
        assert "was not scanned" in captured.err
        assert "Error" not in captured.err

    def test_without_ci_only_warns(self, project: Path, capsys: pytest.CaptureFixture[str]) -> None:
        assert main([str(project)]) == 0
        assert "was not scanned" in capsys.readouterr().err

    def test_findings_still_exit_1(self, project: Path) -> None:
        (project / "bad.py").write_text(PLANTED, encoding="utf-8")
        assert main(["--ci", str(project)]) == 1

    def test_named_file(self, project: Path) -> None:
        assert main(["--ci", str(project / "huge.js")]) == 2

    def test_json_output_is_still_emitted(
        self, project: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["--ci", "--format", "json", str(project)]) == 2
        captured = capsys.readouterr()
        assert json.loads(captured.out) == []
        assert "was not scanned" in captured.err

    def test_allowlisted_file_is_not_a_skipped_one(self, project: Path) -> None:
        scanner = Scanner(exclude_patterns=["huge.js"])
        assert scanner.scan_path(project) == []
        assert scanner.skipped == []

    @needs_permissions
    def test_unreadable_file(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        secret = tmp_path / "locked.py"
        secret.write_text(PLANTED, encoding="utf-8")
        secret.chmod(0)
        try:
            scanner = Scanner()
            assert scanner.scan_path(tmp_path) == []
            assert [path for path, _ in scanner.skipped] == [str(secret)]
            assert scanner.skipped[0][1].startswith("it could not be read (")

            assert main(["--ci", str(tmp_path)]) == 2
            assert f"{secret} was not scanned: it could not be read" in capsys.readouterr().err
        finally:
            secret.chmod(0o644)

    @needs_permissions
    def test_unreadable_file_with_all_text(self, tmp_path: Path) -> None:
        """The binary check cannot read it either; that must not pass it over."""
        secret = tmp_path / "locked.weird"
        secret.write_text(PLANTED, encoding="utf-8")
        secret.chmod(0)
        try:
            scanner = Scanner(text_extensions=None)
            assert scanner.scan_path(tmp_path) == []
            assert [path for path, _ in scanner.skipped] == [str(secret)]
        finally:
            secret.chmod(0o644)

    @needs_permissions
    def test_unreadable_directory(self, tmp_path: Path) -> None:
        locked = tmp_path / "private"
        locked.mkdir()
        (locked / "a.py").write_text(PLANTED, encoding="utf-8")
        locked.chmod(0)
        try:
            scanner = Scanner()
            assert scanner.scan_path(tmp_path) == []
            assert [path for path, _ in scanner.skipped] == [str(locked)]
            assert scanner.skipped[0][1].startswith("the directory could not be read (")
            assert main(["--ci", str(tmp_path)]) == 2
        finally:
            locked.chmod(0o755)

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
    def test_path_that_is_neither_file_nor_directory(self, tmp_path: Path) -> None:
        pipe = tmp_path / "pipe"
        os.mkfifo(pipe)
        scanner = Scanner()
        assert scanner.scan_path(pipe) == []
        assert scanner.skipped == [(str(pipe), "it is not a file or a directory")]


def _git(repo: Path, *args: str) -> None:
    result = subprocess.run(
        ["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid", *args],
        capture_output=True,
        text=True,
        timeout=10,
        cwd=repo,
    )
    assert result.returncode == 0, result.stderr


@needs_git
class TestLockfilesHecklerCannotRead:
    """--diff-only: an unknown or unsupported lockfile counts as unscanned."""

    @pytest.fixture
    def repo(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        _git(tmp_path, "init", "-q")
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("PRE_COMMIT_FROM_REF", raising=False)
        monkeypatch.delenv("PRE_COMMIT_TO_REF", raising=False)
        return tmp_path

    @pytest.mark.parametrize(
        ("name", "reason"),
        [
            ("deps.lock", "it is not a lockfile heckler can read"),
            ("uv.lock", "it is not a lockfile heckler can read"),
            ("Cargo.lock", "cargo lockfiles are not supported yet"),
            ("go.sum", "go lockfiles are not supported yet"),
            ("Gemfile.lock", "ruby lockfiles are not supported yet"),
            ("composer.lock", "composer lockfiles are not supported yet"),
        ],
    )
    def test_fails_ci(
        self, repo: Path, capsys: pytest.CaptureFixture[str], name: str, reason: str
    ) -> None:
        (repo / name).write_text("anything\n", encoding="utf-8")
        _git(repo, "add", name)
        args = ["--scan-deps", "--diff-only", name]

        assert main(["--ci", *args]) == 2
        captured = capsys.readouterr()
        assert f"Warning: {name} was not scanned: {reason}" in captured.err
        assert "Error: 1 item(s) could not be scanned" in captured.err
        assert "No dangerous" not in captured.out

        assert main(["--ci", "--allow-unscanned", *args]) == 0
        assert main(args) == 0

    def test_unsupported_npm_lockfile_version(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        lock = {
            "name": "demo",
            "lockfileVersion": 9,
            "packages": {"node_modules/express": {"version": "4.18.2"}},
        }
        (repo / "package-lock.json").write_text(json.dumps(lock, indent=2), encoding="utf-8")
        _git(repo, "add", "package-lock.json")

        assert main(["--ci", "--scan-deps", "--diff-only", "package-lock.json"]) == 2
        assert "package-lock.json: lockfileVersion 9 is not one heckler can read" in (
            capsys.readouterr().err
        )

    def test_requirement_line_that_cannot_be_read(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (repo / "requirements-dev.txt").write_text(
            "# tools\nhttps://example.test/download\n", encoding="utf-8"
        )
        _git(repo, "add", "requirements-dev.txt")
        args = ["--scan-deps", "--diff-only", "requirements-dev.txt"]

        assert main(["--ci", *args]) == 2
        captured = capsys.readouterr()
        assert (
            'requirements-dev.txt: the added line "https://example.test/download"'
            " does not say which package it installs" in captured.err
        )
        assert main(["--ci", "--allow-unscanned", *args]) == 0

    def test_file_inside_a_changed_package_that_is_too_large(
        self, repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(scanner_module, "_MAX_SCAN_FILE_SIZE", 1024 * 1024)
        pkg = repo / "node_modules" / "express"
        pkg.mkdir(parents=True)
        (pkg / "package.json").write_text('{"version": "4.18.2"}', encoding="utf-8")
        (pkg / "bundle.js").write_bytes(b"/" * (1024 * 1024 + 1))
        lock = {
            "name": "demo",
            "lockfileVersion": 3,
            "packages": {"node_modules/express": {"version": "4.18.2"}},
        }
        (repo / "package-lock.json").write_text(json.dumps(lock, indent=2), encoding="utf-8")
        _git(repo, "add", "package-lock.json")

        assert main(["--ci", "--scan-deps", "--diff-only", "package-lock.json"]) == 2
        assert "bundle.js was not scanned: it is larger than 1 MB" in capsys.readouterr().err
