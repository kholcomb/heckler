"""How much of Unicode's invisible repertoire the detection set covers.

Characters are built with chr() so this file contains none of them.
"""

from __future__ import annotations

import json
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
    Scanner,
)

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
