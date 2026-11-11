"""Which files a directory walk scans, and what it says about the ones it leaves out.

The planted character is built with chr() and sits in a comment that nothing
reads, so this file holds none of the characters and the samples are inert.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from heckler.cli import main
from heckler.scanner import Scanner

ZWSP = chr(0x200B)
PLANTED = f"// note{ZWSP}\n"


def _plant(path: Path, content: str = PLANTED) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _scanned(root: Path, **options: object) -> list[str]:
    """Paths, relative to *root*, of the files a scan reported."""
    findings = Scanner(**options).scan_path(root)  # type: ignore[arg-type]
    return sorted({Path(f.file).relative_to(root).as_posix() for f in findings})


class TestBuildOutput:
    """dist/ and build/ hold what a project ships, and some projects commit them."""

    @pytest.mark.parametrize("name", ["dist", "build"])
    def test_scanned_by_default(self, tmp_path: Path, name: str) -> None:
        _plant(tmp_path / name / "index.js")
        scanner = Scanner()
        assert len(scanner.scan_path(tmp_path)) == 1
        assert scanner.skipped_dirs == []

    def test_cli_fails_on_a_finding_in_dist(self, tmp_path: Path) -> None:
        _plant(tmp_path / "dist" / "index.js")
        assert main(["--ci", str(tmp_path)]) == 1

    def test_can_still_be_skipped_by_configuration(self, tmp_path: Path) -> None:
        _plant(tmp_path / "dist" / "index.js")
        (tmp_path / ".heckler.yml").write_text("extra_skip_dirs:\n  - dist\n", encoding="utf-8")
        assert main(["--ci", "--config", str(tmp_path / ".heckler.yml"), str(tmp_path)]) == 0


SKIPPED_BY_NAME = ["node_modules", "vendor", ".venv", "venv", ".tox", ".eggs", "target"]
SKIPPED_BY_NAME += [".next", ".nuxt", "coverage"]


class TestDirectoriesSkippedByName:
    @pytest.mark.parametrize("name", SKIPPED_BY_NAME)
    def test_skipped_and_recorded(self, tmp_path: Path, name: str) -> None:
        _plant(tmp_path / "pkg" / name / "x" / "index.js")
        scanner = Scanner()
        assert scanner.scan_path(tmp_path) == []
        assert scanner.skipped_dirs == [str(tmp_path / "pkg" / name)]

    @pytest.mark.parametrize("name", SKIPPED_BY_NAME)
    def test_scan_deps_scans_them(self, tmp_path: Path, name: str) -> None:
        _plant(tmp_path / name / "x" / "index.js")
        scanner = Scanner(scan_deps=True)
        assert len(scanner.scan_path(tmp_path)) == 1
        assert scanner.skipped_dirs == []

    @pytest.mark.parametrize("name", [".git", "__pycache__", ".mypy_cache", ".ruff_cache"])
    def test_caches_are_skipped_without_a_mention(self, tmp_path: Path, name: str) -> None:
        _plant(tmp_path / name / "index.js")
        for scanner in (Scanner(), Scanner(scan_deps=True)):
            assert scanner.scan_path(tmp_path) == []
            assert scanner.skipped_dirs == []

    def test_cli_names_what_it_skipped(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _plant(tmp_path / "node_modules" / "pkg" / "index.js")
        _plant(tmp_path / "web" / ".next" / "server.js")
        assert main(["--ci", str(tmp_path)]) == 0
        note = capsys.readouterr().err
        assert "Note: not scanned, skipped by directory name: " in note
        assert str(tmp_path / "node_modules") in note
        assert str(tmp_path / "web" / ".next") in note
        assert "--scan-deps scans dependency directories." in note

    def test_cli_note_counts_past_five(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        for number in range(8):
            _plant(tmp_path / f"pkg{number}" / "node_modules" / "x" / "index.js")
        assert main(["--ci", str(tmp_path)]) == 0
        note = capsys.readouterr().err
        assert note.count("node_modules") == 5
        assert " and 3 more." in note

    def test_cli_says_nothing_when_nothing_was_skipped(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _plant(tmp_path / "src" / "index.js", "const a = 1;\n")
        assert main(["--ci", str(tmp_path)]) == 0
        assert "skipped" not in capsys.readouterr().err

    def test_quiet_drops_the_note(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _plant(tmp_path / "node_modules" / "pkg" / "index.js")
        assert main(["--ci", "--quiet", str(tmp_path)]) == 0
        assert "skipped" not in capsys.readouterr().err

    def test_no_advice_when_scan_deps_is_already_on(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """What is still skipped then is what the configuration names."""
        _plant(tmp_path / "third_party" / "lib.js")
        (tmp_path / ".heckler.yml").write_text(
            "extra_skip_dirs:\n  - third_party\n", encoding="utf-8"
        )
        config = str(tmp_path / ".heckler.yml")
        assert main(["--ci", "--scan-deps", "--config", config, str(tmp_path)]) == 0
        note = capsys.readouterr().err
        assert str(tmp_path / "third_party") in note
        assert "--scan-deps scans" not in note


class TestScripts:
    """A file that starts with #! is a script whatever it is called."""

    def test_extensionless_script_is_scanned(self, tmp_path: Path) -> None:
        _plant(tmp_path / "bin" / "deploy", "#!/bin/sh\n# note" + ZWSP + "\n")
        _plant(tmp_path / "tools" / "run.cgi", "#!/usr/bin/perl\n# note" + ZWSP + "\n")
        assert _scanned(tmp_path) == ["bin/deploy", "tools/run.cgi"]

    def test_without_the_first_line_it_is_not(self, tmp_path: Path) -> None:
        _plant(tmp_path / "bin" / "deploy", "# note" + ZWSP + "\n")
        _plant(tmp_path / "bin" / "late", "\n#!/bin/sh\n# note" + ZWSP + "\n")
        assert _scanned(tmp_path) == []

    def test_an_extension_list_from_the_caller_does_not_turn_it_off(self, tmp_path: Path) -> None:
        _plant(tmp_path / "bin" / "deploy", "#!/bin/sh\n# note" + ZWSP + "\n")
        assert _scanned(tmp_path, text_extensions=frozenset({".js"})) == ["bin/deploy"]


class TestInsideDependencies:
    """The list is shorter inside a dependency, and still covers what runs."""

    def _tree(self, root: Path) -> Path:
        package = root / "node_modules" / "pkg"
        _plant(package / "package.json", '{"scripts": {"install": "node x' + ZWSP + '"}}\n')
        _plant(package / "bin" / "cli", "#!/usr/bin/env node\n" + PLANTED)
        _plant(package / "index.js")
        _plant(package / "README.md", "note" + ZWSP + "\n")
        _plant(package / "data" / "table.json", '{"a": "b' + ZWSP + '"}\n')
        _plant(package / "bin" / "notes", "note" + ZWSP + "\n")
        site = root / ".venv" / "lib" / "python3.12" / "site-packages" / "fast"
        _plant(site / "core.pyx", "# note" + ZWSP + "\n")
        _plant(site / "core.pxd", "# note" + ZWSP + "\n")
        _plant(site / "core.pxi", "# note" + ZWSP + "\n")
        _plant(site / "NOTICE.txt", "note" + ZWSP + "\n")
        return root

    def test_manifest_scripts_and_cython_are_scanned(self, tmp_path: Path) -> None:
        site = ".venv/lib/python3.12/site-packages/fast"
        assert _scanned(self._tree(tmp_path), scan_deps=True) == [
            f"{site}/core.pxd",
            f"{site}/core.pxi",
            f"{site}/core.pyx",
            "node_modules/pkg/bin/cli",
            "node_modules/pkg/index.js",
            "node_modules/pkg/package.json",
        ]

    def test_all_text_adds_the_rest(self, tmp_path: Path) -> None:
        scanned = _scanned(self._tree(tmp_path), scan_deps=True, text_extensions=None)
        assert len(scanned) == 10

    @pytest.mark.parametrize(
        ("name", "content", "expected"),
        [
            ("package.json", "{}\n", True),
            ("index.js", "1;\n", True),
            ("mod.pyx", "x = 1\n", True),
            ("Makefile", "all:\n", True),
            ("cli", "#!/usr/bin/env node\n", True),
            ("cli", "console.log(1);\n", False),
            ("tsconfig.json", "{}\n", False),
            ("README.md", "text\n", False),
        ],
    )
    def test_is_dependency_source(
        self, tmp_path: Path, name: str, content: str, expected: bool
    ) -> None:
        assert Scanner.is_dependency_source(_plant(tmp_path / name, content)) is expected


class TestMoreDefaultNames:
    @pytest.mark.parametrize(
        "name",
        [
            "main.cxx",
            "main.hxx",
            "settings.jsonc",
            "settings.json5",
            "style.less",
            "style.sass",
            "build.gradle.kts",
            "page.html.j2",
            "page.jinja2",
            "index.rst",
            "guide.adoc",
            "fast.pyx",
            "Containerfile",
            "Containerfile.dev",
            "go.mod",
            "go.sum",
            "go.work",
        ],
    )
    def test_scanned_in_a_directory_walk(self, tmp_path: Path, name: str) -> None:
        _plant(tmp_path / "sub" / name, "note" + ZWSP + "\n")
        assert _scanned(tmp_path) == [f"sub/{name}"]


class TestDiffOnlyWithoutALockfile:
    """No lockfile is no packages, and no packages must not come out as clean."""

    @pytest.mark.parametrize("flags", [[], ["--ci"], ["--ci", "--allow-unscanned"]])
    def test_it_is_an_error(self, flags: list[str], capsys: pytest.CaptureFixture[str]) -> None:
        assert main([*flags, "--scan-deps", "--diff-only"]) == 2
        captured = capsys.readouterr()
        assert "Error: --diff-only needs the lockfiles to check" in captured.err
        assert "No dangerous" not in captured.out
