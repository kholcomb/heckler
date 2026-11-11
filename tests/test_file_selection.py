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

    def test_first_line_keeps_a_script_whose_bytes_look_binary(self, tmp_path: Path) -> None:
        """The same bytes without it, or with it on the second line, are left out and counted."""
        body = bytes(range(0x20)) * 64 + ("\n# note" + ZWSP + "\n").encode()
        (tmp_path / "bin").mkdir()
        (tmp_path / "bin" / "deploy").write_bytes(b"#!/bin/sh\n" + body)
        (tmp_path / "bin" / "late").write_bytes(b"\n#!/bin/sh\n" + body)
        (tmp_path / "bin" / "none").write_bytes(body)
        scanner = Scanner()
        assert {Path(f.file).name for f in scanner.scan_path(tmp_path)} == {"deploy"}
        assert scanner.binary == [str(tmp_path / "bin" / "late"), str(tmp_path / "bin" / "none")]

    def test_an_extension_list_from_the_caller_does_not_turn_it_off(self, tmp_path: Path) -> None:
        _plant(tmp_path / "bin" / "deploy", "#!/bin/sh\n# note" + ZWSP + "\n")
        assert _scanned(tmp_path, text_extensions=frozenset({".js"})) == ["bin/deploy"]


class TestEveryTextFile:
    """A walk scans a file for holding text, not for being on a list."""

    @pytest.mark.parametrize(
        "name", ["LICENSE", "notes", "data.custom", "a.b.c", ".hidden", "with space", "x.example"]
    )
    def test_scanned_whatever_it_is_called(self, tmp_path: Path, name: str) -> None:
        _plant(tmp_path / "sub" / name, "note" + ZWSP + "\n")
        assert _scanned(tmp_path) == [f"sub/{name}"]

    def test_an_extension_on_the_list_is_scanned_whatever_the_file_holds(
        self, tmp_path: Path
    ) -> None:
        """What extra_extensions adds to: a name that vouches for the file."""
        noise = bytes(range(256)) * 4 + ZWSP.encode()
        (tmp_path / "a.custom").write_bytes(noise)
        (tmp_path / "b.other").write_bytes(noise)
        scanner = Scanner(text_extensions=frozenset({".custom"}))
        assert {Path(f.file).name for f in scanner.scan_path(tmp_path)} == {"a.custom"}
        assert scanner.binary == [str(tmp_path / "b.other")]

    def test_extra_extensions_from_the_configuration(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        noise = bytes(range(256)) * 4 + ZWSP.encode()
        (tmp_path / "a.custom").write_bytes(noise)
        config = tmp_path / ".heckler.yml"
        config.write_text("extra_extensions:\n  - .custom\n", encoding="utf-8")
        assert main(["--ci", str(tmp_path)]) == 0
        note = f"Note: not scanned, binary by content: {tmp_path / 'a.custom'}."
        assert note in capsys.readouterr().err
        assert main(["--ci", "--config", str(config), str(tmp_path)]) == 1

    def test_all_text_does_not_drop_the_extra_extensions(self, tmp_path: Path) -> None:
        """--all-text scans more, never less."""
        (tmp_path / "a.custom").write_bytes(bytes(range(256)) * 4 + ZWSP.encode())
        config = tmp_path / ".heckler.yml"
        config.write_text("extra_extensions:\n  - .custom\n", encoding="utf-8")
        assert main(["--ci", "--all-text", "--config", str(config), str(tmp_path)]) == 1


class TestFilesPassedByName:
    """Always scanned, unless --skip-binary asks for the rule a walk follows."""

    def _files(self, root: Path) -> tuple[Path, Path, Path]:
        noise = bytes(range(256)) * 4 + ZWSP.encode()
        blob, source = root / "blob", root / "blob.js"
        blob.write_bytes(noise)
        source.write_bytes(noise)
        return blob, source, _plant(root / "notes", "note" + ZWSP + "\n")

    def test_scanned_whatever_it_holds(self, tmp_path: Path) -> None:
        blob, _source, _text = self._files(tmp_path)
        scanner = Scanner()
        assert scanner.scan_path(blob) != []
        assert scanner.binary == []

    def test_skip_binary_leaves_out_what_a_walk_would(self, tmp_path: Path) -> None:
        blob, source, text = self._files(tmp_path)
        scanner = Scanner(skip_binary=True)
        assert scanner.scan_path(blob) == []
        assert scanner.binary == [str(blob)]
        assert len(scanner.scan_path(text)) == 1
        assert scanner.scan_path(source) != [], "the name marks it as source"
        assert scanner.binary == [str(blob)]

    def test_skip_binary_reads_a_file_that_is_mostly_text(self, tmp_path: Path) -> None:
        """Padding at the top makes a file look binary. It does not make it binary."""
        padded = tmp_path / "notes"
        text = "a line of plain text\n" * 80 + f"name = 'a{ZWSP}b'\n"
        padded.write_bytes(b"# " + b"\x00" * 300 + b"\n" + text.encode())
        names = [f.char_name for f in Scanner().scan_path(padded)]
        assert names == ["Null", "Zero Width Space"]
        scanner = Scanner(skip_binary=True)
        names = [f.char_name for f in scanner.scan_path(padded)]
        assert names == ["Zero Width Space (in a file that looks binary)"]
        assert scanner.binary == []

    def test_cli_names_what_it_left_out(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        blob, _source, text = self._files(tmp_path)
        assert main(["--ci", "--no-color", "--skip-binary", str(blob), str(text)]) == 1
        captured = capsys.readouterr()
        assert f"Note: not scanned, binary by content: {blob}." in captured.err
        assert str(text) in captured.out
        assert str(blob) not in captured.out

    def test_one_nul_does_not_leave_a_file_out(self, tmp_path: Path) -> None:
        """The byte that opted a file out of the hook when pre-commit picked the text files."""
        target = tmp_path / "notes"
        target.write_bytes(b"\x00 note" + ZWSP.encode() + b"\n" + b"more text\n" * 50)
        scanner = Scanner(skip_binary=True)
        assert [f.char_name for f in scanner.scan_path(target)] == ["Null", "Zero Width Space"]

    def test_hook_takes_every_file_and_has_heckler_decide(self) -> None:
        hooks = Path(__file__).parent.parent / ".pre-commit-hooks.yaml"
        source_hook = hooks.read_text(encoding="utf-8").split("- id: heckler-lockfile")[0]
        assert "  types: [file]\n" in source_hook
        assert "  entry: heckler --ci --skip-binary\n" in source_hook


class TestInsideDependencies:
    """Inside a dependency a walk keeps to code, and that covers what runs."""

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

    @pytest.mark.parametrize("option", [{"all_text": True}, {"text_extensions": None}])
    def test_all_text_adds_the_rest(self, tmp_path: Path, option: dict[str, object]) -> None:
        scanned = _scanned(self._tree(tmp_path), scan_deps=True, **option)
        assert len(scanned) == 10

    def test_the_project_around_them_is_scanned_as_ever(self, tmp_path: Path) -> None:
        _plant(tmp_path / "docs" / "NOTES", "note" + ZWSP + "\n")
        scanned = _scanned(self._tree(tmp_path), scan_deps=True)
        assert "docs/NOTES" in scanned
        assert "node_modules/pkg/README.md" not in scanned

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
