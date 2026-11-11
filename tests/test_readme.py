"""The README shows real output and real numbers. These tests fail when it drifts.

The example project is built here with chr(), so neither this file nor the
README holds any of the characters it is about.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from heckler.characters import DANGEROUS_UNICODE_RE
from heckler.cli import build_parser, main
from heckler.scanner import DEFAULT_TEXT_EXTENSIONS, KNOWN_FILENAME_PREFIXES, KNOWN_FILENAMES

REPO_ROOT = Path(__file__).parent.parent
README = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

# The project the README's example scans. Inert text: the characters sit in
# string literals and a comment, and nothing reads them back.
EXAMPLE_COMMAND = "$ heckler suspect-project/"
EXAMPLE_FILES = {
    "api.js": (
        "// Client for the billing API.\n"
        'const endpoint = "https://api.example.test/v2";\n'
        'const label = "v2' + chr(0xFE01) + chr(0xFE02) + '";\n'
    ),
    "auth.js": (
        "// Only admins may delete.\n"
        'const role = "user"; // ' + chr(0x202E) + "nimda" + chr(0x202C) + "\n"
    ),
    "config.py": ('name = "ad' + chr(0x200B) + 'min"\ntitle = "co' + chr(0xAD) + 'operate"\n'),
}


def _section(start: str, end: str) -> str:
    """The README between two headings."""
    return README[README.index(start) : README.index(end)]


class TestExample:
    def _real_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> str:
        project = tmp_path / "suspect-project"
        project.mkdir()
        for name, text in EXAMPLE_FILES.items():
            (project / name).write_text(text, encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)  # no ::error annotations
        assert main(["--no-color", "suspect-project/"]) == 0
        return capsys.readouterr().out.replace("\\", "/")

    def test_example_is_the_real_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        match = re.search(
            r"^```\n" + re.escape(EXAMPLE_COMMAND) + r"\n(.*?)^```$",
            README,
            re.DOTALL | re.MULTILINE,
        )
        assert match, "example block not found in README.md"
        real = self._real_output(tmp_path, monkeypatch, capsys)
        assert match.group(1).strip("\n") == real.strip("\n"), (
            "README.md's example is not what heckler prints for the project in"
            " tests/test_readme.py; paste the real output into the README"
        )

    def test_readme_itself_holds_none_of_the_characters(self) -> None:
        assert DANGEROUS_UNICODE_RE.search(README) is None


class TestNumbers:
    def test_codepoint_count(self) -> None:
        flagged = sum(
            1
            for cp in range(0x110000)
            if not 0xD800 <= cp <= 0xDFFF and DANGEROUS_UNICODE_RE.fullmatch(chr(cp))
        )
        claims = re.findall(r"([0-9][0-9,]*) codepoints", README)
        assert claims, "no codepoint count found in README.md"
        assert set(claims) == {f"{flagged:,}"}

    def test_extension_count(self) -> None:
        claims = {int(n) for n in re.findall(r"([0-9]+)\+ file extensions", README)}
        assert len(claims) == 1, claims
        (claimed,) = claims
        assert claimed <= len(DEFAULT_TEXT_EXTENSIONS) < claimed + 10


class TestLanguageSupport:
    SECTION = _section("## Language Support", "### Dependency / Supply Chain Coverage")

    def test_table_lists_exactly_the_default_extensions(self) -> None:
        rows = [line for line in self.SECTION.splitlines() if line.startswith("|")]
        in_table = set(re.findall(r"`(\.[A-Za-z0-9]+)`", "\n".join(rows)))
        assert sorted(DEFAULT_TEXT_EXTENSIONS - in_table) == [], "scanned but not in the table"
        assert sorted(in_table - DEFAULT_TEXT_EXTENSIONS) == [], "in the table but not scanned"

    def test_named_files_are_scanned(self) -> None:
        paragraph = next(
            line for line in self.SECTION.splitlines() if line.startswith("Well-known files")
        )
        for name in re.findall(r"`([^`]+)`", paragraph):
            if name.endswith(".*"):
                assert name[:-1] in KNOWN_FILENAME_PREFIXES, name
            else:
                assert name in KNOWN_FILENAMES or name.startswith(KNOWN_FILENAME_PREFIXES), name


class TestCliReference:
    def test_every_option_is_documented(self) -> None:
        section = _section("## CLI Reference", "## Library API")
        options = [
            option
            for action in build_parser()._actions
            for option in action.option_strings
            if option.startswith("--") and option not in ("--help", "--version")
        ]
        assert len(options) > 10
        assert [option for option in options if f"`{option}" not in section] == []
