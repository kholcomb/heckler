"""How much of Unicode's invisible repertoire the detection set covers.

Characters are built with chr() so this file contains none of them.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from heckler.characters import (
    DANGEROUS_UNICODE_RE,
    Severity,
    ThreatCategory,
    get_char_info,
)
from heckler.formatters import format_sarif
from heckler.scanner import (
    _MAX_FINDINGS_PER_FILE,
    DEFAULT_TEXT_EXTENSIONS,
    KNOWN_FILENAME_PREFIXES,
    KNOWN_FILENAMES,
    Scanner,
)

REPO_ROOT = Path(__file__).parent.parent

# Default_Ignorable_Code_Point, from Unicode's DerivedCoreProperties.txt:
# 4,174 code points that renderers are told to draw nothing for.
DEFAULT_IGNORABLE = [
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
]
SPACES_AND_SEPARATORS = [
    0x00A0,
    0x1680,
    *range(0x2000, 0x200B),
    0x2028,
    0x2029,
    0x202F,
    0x205F,
    0x3000,
]
CONTROLS = [cp for cp in (*range(0x00, 0x20), *range(0x7F, 0xA0)) if cp not in (0x09, 0x0A, 0x0D)]


def flagged(cp: int) -> bool:
    return DANGEROUS_UNICODE_RE.fullmatch(chr(cp)) is not None


def all_flagged() -> list[int]:
    return [cp for cp in range(0x110000) if not 0xD800 <= cp <= 0xDFFF and flagged(cp)]


class TestDetectionSet:
    def test_every_default_ignorable_code_point(self) -> None:
        code_points = [cp for lo, hi in DEFAULT_IGNORABLE for cp in range(lo, hi + 1)]
        assert len(code_points) == 4174
        assert [f"U+{cp:04X}" for cp in code_points if not flagged(cp)] == []

    def test_every_space_and_separator_but_the_ordinary_space(self) -> None:
        assert [f"U+{cp:04X}" for cp in SPACES_AND_SEPARATORS if not flagged(cp)] == []
        assert not flagged(0x20)

    def test_every_control_character_but_tab_and_line_endings(self) -> None:
        assert len(CONTROLS) == 62
        assert [f"U+{cp:04X}" for cp in CONTROLS if not flagged(cp)] == []
        assert not any(flagged(cp) for cp in (0x09, 0x0A, 0x0D))

    @pytest.mark.parametrize("cp", [0x2800, 0xFFFC, 0x13441, 0x13442, 0x16FE4, 0x1D159])
    def test_blank_glyphs(self, cp: int) -> None:
        assert flagged(cp)

    @pytest.mark.parametrize(
        "cp",
        [
            *range(0x20, 0x7F),  # printable ASCII
            0x00E9,  # Latin letter with an accent
            0x4E2D,  # CJK ideograph
            0xAC00,  # Hangul syllable
            0x0600,  # Arabic number sign: a format character, but a visible one
            0x26A0,  # warning sign
            0x1F600,  # emoji
            0x20E3,  # combining enclosing keycap
            0xE000,  # private use
            0xFFFD,  # replacement character
            0xDFFFF,  # just below the default-ignorable block of plane 14
            0xE1000,  # just above it
        ],
    )
    def test_ordinary_text_is_left_alone(self, cp: int) -> None:
        assert not flagged(cp)

    def test_every_flagged_code_point_has_a_name_and_severity(self) -> None:
        unnamed = [
            f"U+{cp:04X}" for cp in all_flagged() if get_char_info(cp).name.startswith("Unknown")
        ]
        assert unnamed == []


class TestSeverities:
    @pytest.mark.parametrize(
        ("cp", "category", "severity"),
        [
            (0x180F, ThreatCategory.VARIATION_SELECTOR, Severity.HIGH),
            (0xE0000, ThreatCategory.INVISIBLE_FORMAT, Severity.HIGH),
            (0xE0FFF, ThreatCategory.INVISIBLE_FORMAT, Severity.HIGH),
            (0xFFF0, ThreatCategory.INVISIBLE_FORMAT, Severity.HIGH),
            (0x2065, ThreatCategory.INVISIBLE_FORMAT, Severity.HIGH),
            (0xE0041, ThreatCategory.TAG_CHARACTER, Severity.HIGH),
            (0xE0100, ThreatCategory.VARIATION_SELECTOR, Severity.CRITICAL),
            (0x1BCA0, ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM),
            (0x1D173, ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM),
            (0x13441, ThreatCategory.INVISIBLE_IDENTIFIER, Severity.MEDIUM),
            (0x001B, ThreatCategory.CONTROL_CHARACTER, Severity.HIGH),
            (0x0008, ThreatCategory.CONTROL_CHARACTER, Severity.MEDIUM),
            (0x0000, ThreatCategory.CONTROL_CHARACTER, Severity.MEDIUM),
            (0x0085, ThreatCategory.CONTROL_CHARACTER, Severity.MEDIUM),
            (0x0092, ThreatCategory.CONTROL_CHARACTER, Severity.MEDIUM),
            (0x000C, ThreatCategory.CONTROL_CHARACTER, Severity.INFO),
        ],
    )
    def test_classification(self, cp: int, category: ThreatCategory, severity: Severity) -> None:
        info = get_char_info(cp)
        assert (info.category, info.severity) == (category, severity)

    def test_reserved_code_point_is_reported(self) -> None:
        findings = Scanner().scan_text("x = '" + chr(0xE0FFF) + "'")
        assert [(f.codepoint_hex, f.char_name) for f in findings] == [
            ("U+E0FFF", "Reserved Default Ignorable Code Point")
        ]

    def test_escape_sequence_is_reported(self) -> None:
        findings = Scanner().scan_text("print('" + chr(0x1B) + "[2K hidden')")
        assert [(f.char_name, f.severity) for f in findings] == [("Escape", Severity.HIGH)]

    def test_form_feed_is_listed_only_at_info(self) -> None:
        page_break = "def a(): pass\n" + chr(0x0C) + "\ndef b(): pass\n"
        assert Scanner().scan_text(page_break) == []
        listed = Scanner(severity_threshold=Severity.INFO).scan_text(page_break)
        assert [f.char_name for f in listed] == ["Form Feed"]

    def test_tabs_and_windows_line_endings_are_not_findings(self) -> None:
        assert Scanner(severity_threshold=Severity.INFO).scan_text("a\tb\r\nc\r\n") == []

    def test_control_character_can_be_suppressed_by_code_point(self) -> None:
        text = "# heckler-ignore-next-line U+001B\ncolour = '" + chr(0x1B) + "[31m'\n"
        assert Scanner().scan_text(text) == []

    def test_sarif_has_a_rule_for_control_characters(self) -> None:
        sarif = json.loads(format_sarif(Scanner().scan_text("x" + chr(0x1B))))
        run = sarif["runs"][0]
        assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
            "glassworm/control-character"
        ]
        assert run["results"][0]["level"] == "error"


class TestFloodGuards:
    def test_nul_is_reported_once_per_file(self) -> None:
        text = "a" + chr(0) * 500 + "\nb" + chr(0) * 500 + "\n"
        findings = Scanner().scan_text(text)
        assert [(f.line, f.column, f.char_name) for f in findings] == [(1, 2, "Null")]

    def test_findings_per_file_are_capped(self, capsys: pytest.CaptureFixture[str]) -> None:
        text = chr(0x200B) * (_MAX_FINDINGS_PER_FILE + 50)
        findings = Scanner().scan_text(text, "bundle.js")
        assert len(findings) == _MAX_FINDINGS_PER_FILE
        assert "bundle.js: stopped after" in capsys.readouterr().err

    def test_cap_is_per_file(self, tmp_path: Path) -> None:
        for name in ("a.js", "b.js"):
            (tmp_path / name).write_text(chr(0x200B) * 3, encoding="utf-8")
        assert len(Scanner().scan_path(tmp_path)) == 6


class TestShellFallback:
    """scripts/heckler-scan.sh carries its own copy of the list; keep them equal."""

    def test_pattern_matches_what_the_scanner_reports_by_default(self) -> None:
        script = (REPO_ROOT / "scripts" / "heckler-scan.sh").read_text(encoding="utf-8")
        match = re.search(r"^PATTERN='\[(.*)\]'$", script, re.MULTILINE)
        assert match, "PATTERN line not found"
        tokens = re.findall(r"\\x\{([0-9A-Fa-f]+)\}(?:-\\x\{([0-9A-Fa-f]+)\})?", match.group(1))
        in_script = {cp for lo, hi in tokens for cp in range(int(lo, 16), int(hi or lo, 16) + 1)}

        # The script has no severities, so it carries what the scanner reports
        # at its default threshold: everything except the INFO-level Form Feed.
        reported = {cp for cp in all_flagged() if get_char_info(cp).severity >= Severity.LOW}

        missing = sorted(reported - in_script)
        extra = sorted(in_script - reported)
        assert [f"U+{cp:04X}" for cp in missing] == [], "in the Python scanner but not the script"
        assert [f"U+{cp:04X}" for cp in extra] == [], "in the script but not the Python scanner"

    def test_file_list_matches_what_the_scanner_scans_by_default(self) -> None:
        script = (REPO_ROOT / "scripts" / "heckler-scan.sh").read_text(encoding="utf-8")
        block = script[script.index("INCLUDES=(") : script.index("# END GENERATED INCLUDES")]
        in_script = set(re.findall(r"--include='([^']*)'", block))

        scanned = (
            {f"*{extension}" for extension in DEFAULT_TEXT_EXTENSIONS}
            | set(KNOWN_FILENAMES)
            | {f"{prefix}*" for prefix in KNOWN_FILENAME_PREFIXES}
        )
        hint = "; run: python scripts/sync_shell_includes.py"
        assert sorted(scanned - in_script) == [], "scanned by Python but not by the script" + hint
        assert sorted(in_script - scanned) == [], "scanned by the script but not by Python" + hint
        # Nothing else selects files: every --include in the script is in the block.
        assert script.count("--include=") == len(in_script)

    def test_file_list_is_what_the_generator_writes(self) -> None:
        """The block is generated; an edit by hand, even a harmless one, is a drift."""
        path = REPO_ROOT / "scripts" / "sync_shell_includes.py"
        spec = importlib.util.spec_from_file_location("sync_shell_includes", path)
        assert spec and spec.loader
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)

        script = (REPO_ROOT / "scripts" / "heckler-scan.sh").read_text(encoding="utf-8")
        assert generator.replace_block(script) == script
        assert generator.main(["--check"]) == 0

    def test_generator_check_fails_on_a_stale_list(self, tmp_path: Path) -> None:
        stale = tmp_path / "heckler-scan.sh"
        script = (REPO_ROOT / "scripts" / "heckler-scan.sh").read_text(encoding="utf-8")
        stale.write_text(script.replace(" --include='*.py'", ""), encoding="utf-8")
        generator = tmp_path / "sync_shell_includes.py"
        shutil.copy(REPO_ROOT / "scripts" / "sync_shell_includes.py", generator)

        check = subprocess.run(
            [sys.executable, str(generator), "--check"], capture_output=True, text=True, timeout=60
        )
        assert check.returncode == 1
        assert "does not match" in check.stderr
        assert "--include='*.py'" not in stale.read_text(encoding="utf-8")

        subprocess.run([sys.executable, str(generator)], check=True, timeout=60)
        assert stale.read_text(encoding="utf-8") == script


def _grep_supports_pcre() -> bool:
    if os.name == "nt" or shutil.which("bash") is None or shutil.which("grep") is None:
        return False
    try:
        probe = subprocess.run(
            ["grep", "-P", "x"], input="x\n", capture_output=True, text=True, timeout=10
        )
    except OSError:
        return False
    return probe.returncode == 0


@pytest.mark.skipif(not _grep_supports_pcre(), reason="needs bash and a grep with -P")
class TestShellFallbackRuns:
    """Run the script itself on small files written here."""

    SCRIPT = REPO_ROOT / "scripts" / "heckler-scan.sh"

    def _run(self, directory: Path, **env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(self.SCRIPT), str(directory)],
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, **env},
        )

    def test_clean_directory_passes(self, tmp_path: Path) -> None:
        text = "x = 1\n# caf" + chr(0xE9) + "\ttab\n" + chr(0x0C) + "\ny = 2\r\n"
        (tmp_path / "ok.py").write_text(text, encoding="utf-8")
        result = self._run(tmp_path)
        assert result.returncode == 0, result.stdout

    @pytest.mark.parametrize(
        "cp",
        [0x200B, 0x202E, 0xFE01, 0x180F, 0x2028, 0x3000, 0xE0041, 0xE0FFF, 0x1BCA0, 0x1B, 0x85],
    )
    def test_each_kind_of_character_is_reported(self, tmp_path: Path, cp: int) -> None:
        (tmp_path / "sample.js").write_text("v = 'a" + chr(cp) + "b'\n", encoding="utf-8")
        result = self._run(tmp_path)
        assert result.returncode == 1
        assert "sample.js" in result.stdout

    @pytest.mark.parametrize(
        "name",
        [
            "Makefile",
            "Dockerfile",
            "Dockerfile.dev",
            "Jenkinsfile",
            ".env",
            ".env.example",
            ".gitattributes",
            ".cursorrules",
            "rule.mdc",
            "worker.mts",
            "main.cc",
            "page.htm",
            "view.html.erb",
            "notebook.ipynb",
            "hooks.pth",
            "sub/dir/deep.zig",
        ],
    )
    def test_same_files_as_the_python_scanner(self, tmp_path: Path, name: str) -> None:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("v = 'a" + chr(0x200B) + "b'\n", encoding="utf-8")
        assert len(Scanner().scan_path(tmp_path)) == 1
        result = self._run(tmp_path)
        assert result.returncode == 1, result.stdout
        assert Path(name).name in result.stdout

    @pytest.mark.parametrize("name", ["notes", "data.bin", "Dockerfiles", "env", "x.example"])
    def test_same_files_left_out_as_the_python_scanner(self, tmp_path: Path, name: str) -> None:
        (tmp_path / name).write_text("v = 'a" + chr(0x200B) + "b'\n", encoding="utf-8")
        assert Scanner().scan_path(tmp_path) == []
        assert self._run(tmp_path).returncode == 0

    def test_nul_byte_does_not_hide_the_file(self, tmp_path: Path) -> None:
        (tmp_path / "hidden.js").write_bytes(
            b"// header" + bytes([0]) + b"\n" + ("v = 'a" + chr(0x200B) + "b'\n").encode()
        )
        result = self._run(tmp_path)
        assert result.returncode == 1
        assert "hidden.js" in result.stdout

    def test_output_cannot_drive_the_terminal(self, tmp_path: Path) -> None:
        (tmp_path / "colour.py").write_text(
            "print('" + chr(0x1B) + "[2K gone')\n", encoding="utf-8"
        )
        result = self._run(tmp_path)
        assert result.returncode == 1
        assert chr(0x1B) not in result.stdout
        assert "^[[2K" in result.stdout

    def test_long_listing_does_not_break_the_pipe(self, tmp_path: Path) -> None:
        line = "padding " * 20 + chr(0x200B) + "\n"
        (tmp_path / "many.js").write_text(line * 3000, encoding="utf-8")
        result = self._run(tmp_path)
        assert result.returncode == 1
        assert "(3000 occurrence(s))" in result.stdout
        assert "... and 2950 more." in result.stdout

    def test_non_utf8_locale_is_never_reported_clean(self, tmp_path: Path) -> None:
        (tmp_path / "sample.js").write_text("v = 'a" + chr(0x200B) + "b'\n", encoding="utf-8")
        result = self._run(tmp_path, LC_ALL="C", LANG="C")
        # Either the script switched to a UTF-8 locale and found it, or it
        # refused to run. What it must not do is pass.
        assert result.returncode in (1, 2)
        if result.returncode == 2:
            assert "locale" in result.stderr
