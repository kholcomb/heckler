"""Emoji contain variation selectors and joiners; those are not attacks.

All characters are written as escapes so this file stays clean under
heckler's own scan.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from heckler.characters import Severity, ThreatCategory, is_emoji_context
from heckler.config import load_config
from heckler.formatters.text import format_text
from heckler.scanner import Scanner

WARNING = "\u26a0"  # takes U+FE0F to render as an emoji
HEART = "\u2764"
FLAG = "\U0001f3f3"
WOMAN = "\U0001f469"
LAPTOP = "\U0001f4bb"
FIRE = "\U0001f525"
SKIN_TONE = "\U0001f3fd"
VS15, VS16 = "\ufe0e", "\ufe0f"
ZWJ = "\u200d"
KEYCAP = "\u20e3"

WELL_FORMED = [
    pytest.param(f"# {WARNING}{VS16} Warning", id="emoji-presentation"),
    pytest.param(f"# {WARNING}{VS15} Warning", id="text-presentation"),
    pytest.param(f'x = "{FLAG}{VS16}"', id="supplementary-plane-base"),
    pytest.param(f"1{VS16}{KEYCAP} first", id="keycap"),
    pytest.param(f"#{VS16}{KEYCAP}", id="keycap-number-sign"),
    pytest.param(f"{WOMAN}{ZWJ}{LAPTOP}", id="zwj-profession"),
    pytest.param(f"{WOMAN}{SKIN_TONE}{ZWJ}{LAPTOP}", id="zwj-with-skin-tone"),
    pytest.param(f"{HEART}{VS16}{ZWJ}{FIRE}", id="zwj-after-selector"),
    pytest.param(f"{FLAG}{VS16}{ZWJ}\U0001f308", id="rainbow-flag"),
    pytest.param(f"{WARNING}{VS16} and {HEART}{VS16}", id="two-on-a-line"),
]


class TestWellFormedEmoji:
    @pytest.mark.parametrize("text", WELL_FORMED)
    def test_not_reported_by_default(self, text: str) -> None:
        assert Scanner().scan_text(text) == []

    @pytest.mark.parametrize("text", WELL_FORMED)
    def test_still_visible_at_info(self, text: str) -> None:
        findings = Scanner(severity_threshold=Severity.INFO).scan_text(text)
        assert findings
        assert all(f.severity == Severity.INFO for f in findings)
        assert all(f.char_name.endswith("(in emoji)") for f in findings)

    def test_category_is_unchanged(self) -> None:
        findings = Scanner(severity_threshold=Severity.INFO).scan_text(f"{WARNING}{VS16}")
        assert [f.category for f in findings] == [ThreatCategory.VARIATION_SELECTOR]

    def test_info_finding_is_not_labelled_as_an_attack(self) -> None:
        findings = Scanner(severity_threshold=Severity.INFO).scan_text(f"{WARNING}{VS16}")
        assert "GLASSWORM" not in format_text(findings, color=False)


class TestStillFlagged:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            pytest.param(f'x = "{VS16}"', [Severity.CRITICAL], id="selector-after-punctuation"),
            pytest.param(f"a{VS16}", [Severity.CRITICAL], id="selector-after-letter"),
            pytest.param(VS16, [Severity.CRITICAL], id="selector-at-line-start"),
            pytest.param(f"1{VS16}", [Severity.CRITICAL], id="digit-without-keycap"),
            pytest.param(f"{WARNING}\ufe00", [Severity.CRITICAL], id="other-selector-after-emoji"),
            pytest.param(
                f"{WARNING}{VS16}{VS16}",
                [Severity.CRITICAL] * 2,
                id="run-of-two",
            ),
            pytest.param(
                f"{WARNING}{VS16}\ufe01\ufe02",
                [Severity.CRITICAL] * 3,
                id="payload-behind-an-emoji",
            ),
            pytest.param(
                f"{WARNING}{VS16}\U000e0100",
                [Severity.CRITICAL] * 2,
                id="supplement-run",
            ),
            pytest.param(f"ad{ZWJ}min", [Severity.MEDIUM], id="joiner-between-letters"),
            pytest.param(f"{WOMAN}{ZWJ}x", [Severity.MEDIUM], id="joiner-before-letter"),
            pytest.param(f"x{ZWJ}{LAPTOP}", [Severity.MEDIUM], id="joiner-after-letter"),
            pytest.param(f"{WOMAN}{ZWJ}", [Severity.MEDIUM], id="joiner-at-line-end"),
            pytest.param(
                f"a{VS16}{ZWJ}{FIRE}",
                [Severity.CRITICAL, Severity.MEDIUM],
                id="joiner-after-misplaced-selector",
            ),
            pytest.param(f"{WARNING}\u200b", [Severity.MEDIUM], id="zero-width-space-after-emoji"),
        ],
    )
    def test_reported(self, text: str, expected: list[Severity]) -> None:
        assert [f.severity for f in Scanner().scan_text(text)] == expected

    def test_allow_emoji_off_restores_strict_behaviour(self) -> None:
        findings = Scanner(allow_emoji=False).scan_text(f"# {WARNING}{VS16} Warning")
        assert [f.severity for f in findings] == [Severity.CRITICAL]

    def test_dependency_code_gets_the_same_rule(self) -> None:
        text = f'log("{WARNING}{VS16}"); x = `\ufe01\ufe02`;'
        findings = Scanner(scan_deps=True).scan_text(text, "node_modules/pkg/index.js")
        assert [f.codepoint for f in findings] == [0xFE01, 0xFE02]


BLACK_FLAG = "\U0001f3f4"
CANCEL_TAG = "\U000e007f"


def tags(text: str) -> str:
    """*text* spelled in tag characters, the invisible mirror of ASCII."""
    return "".join(chr(0xE0000 + ord(ch)) for ch in text)


class TestSubdivisionFlags:
    """England, Scotland and Wales: the only emoji that are built from tags."""

    @pytest.mark.parametrize("region", ["gbeng", "gbsct", "gbwls"])
    def test_standard_flag_is_info(self, region: str) -> None:
        text = f"# {BLACK_FLAG}{tags(region)}{CANCEL_TAG} home nations"
        assert Scanner().scan_text(text) == []
        listed = Scanner(severity_threshold=Severity.INFO).scan_text(text)
        assert len(listed) == 6
        assert all(f.severity == Severity.INFO for f in listed)
        assert all(f.category == ThreatCategory.TAG_CHARACTER for f in listed)
        assert all(f.char_name.endswith("(in emoji)") for f in listed)

    def test_two_flags_on_a_line(self) -> None:
        flag = f"{BLACK_FLAG}{tags('gbsct')}{CANCEL_TAG}"
        assert Scanner().scan_text(f"{flag} v {flag}") == []

    @pytest.mark.parametrize(
        ("text", "reported"),
        [
            pytest.param(f"{BLACK_FLAG}{tags('usca')}{CANCEL_TAG}", 5, id="other-region"),
            pytest.param(f"{BLACK_FLAG}{tags('gbeng')}", 5, id="no-cancel-tag"),
            pytest.param(f"{BLACK_FLAG}{tags('gben')}{CANCEL_TAG}", 5, id="short"),
            pytest.param(f"{BLACK_FLAG}{tags('gbengx')}{CANCEL_TAG}", 7, id="long"),
            pytest.param(f"{BLACK_FLAG}{tags('GBENG')}{CANCEL_TAG}", 6, id="upper-case"),
            pytest.param(f"{tags('gbeng')}{CANCEL_TAG}", 6, id="no-flag"),
            pytest.param(f"{FLAG}{tags('gbeng')}{CANCEL_TAG}", 6, id="white-flag"),
            pytest.param(f"{BLACK_FLAG} {tags('gbeng')}{CANCEL_TAG}", 6, id="space-after-flag"),
            pytest.param(f"x = '{tags('hidden text')}'", 11, id="plain-tag-run"),
        ],
    )
    def test_any_other_tag_run_is_high(self, text: str, reported: int) -> None:
        findings = Scanner().scan_text(text)
        assert len(findings) == reported
        assert all(f.severity == Severity.HIGH for f in findings)

    def test_tags_after_a_complete_flag_are_reported(self) -> None:
        text = f"{BLACK_FLAG}{tags('gbeng')}{CANCEL_TAG}{tags('more')}"
        findings = Scanner().scan_text(text)
        assert [f.column for f in findings] == [8, 9, 10, 11]
        assert all(f.severity == Severity.HIGH for f in findings)

    def test_tags_before_a_flag_are_reported(self) -> None:
        text = f"{tags('pre')}{BLACK_FLAG}{tags('gbwls')}{CANCEL_TAG}"
        assert [f.column for f in Scanner().scan_text(text)] == [1, 2, 3]

    def test_allow_emoji_off_flags_the_flag_too(self) -> None:
        text = f"{BLACK_FLAG}{tags('gbeng')}{CANCEL_TAG}"
        assert len(Scanner(allow_emoji=False).scan_text(text)) == 6

    def test_long_tag_run_is_scanned_quickly(self) -> None:
        text = BLACK_FLAG + tags("a" * 5000)
        assert len(Scanner().scan_text(text)) == 5000


class TestSelectorDensity:
    """Many selectors on one line are reported once, though each sits in an emoji."""

    ROW = f"| {WARNING}{VS16} "

    def test_a_handful_is_fine(self) -> None:
        assert Scanner().scan_text(self.ROW * 10 + "|") == []

    def test_more_is_reported_once(self) -> None:
        findings = Scanner().scan_text("x = 1\n" + self.ROW * 11 + "|\n")
        assert [(f.line, f.column, f.codepoint, f.severity) for f in findings] == [
            (2, 4, 0xFE0F, Severity.LOW)
        ]
        assert findings[0].char_name == "11 emoji presentation selectors on one line"
        assert findings[0].category == ThreatCategory.VARIATION_SELECTOR

    def test_text_and_emoji_selectors_both_count(self) -> None:
        line = f"{WARNING}{VS15}{WARNING}{VS16}" * 6
        findings = Scanner().scan_text(line)
        assert [f.char_name for f in findings] == ["12 emoji presentation selectors on one line"]

    def test_count_is_per_line(self) -> None:
        text = (self.ROW * 8 + "|\n") * 5
        assert Scanner().scan_text(text) == []

    def test_joiners_do_not_count(self) -> None:
        assert Scanner().scan_text(f"{WOMAN}{ZWJ}{LAPTOP} " * 20) == []

    def test_listed_at_info_alongside_the_selectors(self) -> None:
        findings = Scanner(severity_threshold=Severity.INFO).scan_text(self.ROW * 11)
        assert [f.severity for f in findings] == [Severity.INFO] * 11 + [Severity.LOW]

    def test_not_reported_above_its_severity(self) -> None:
        assert Scanner(severity_threshold=Severity.MEDIUM).scan_text(self.ROW * 11) == []

    def test_can_be_suppressed(self) -> None:
        scanner = Scanner()
        assert scanner.scan_text("# heckler-ignore-next-line\n" + self.ROW * 11) == []
        assert scanner.suppressed == {"<string>": 1}

    def test_allow_emoji_off_reports_each_selector_instead(self) -> None:
        findings = Scanner(allow_emoji=False).scan_text(self.ROW * 11)
        assert [f.severity for f in findings] == [Severity.CRITICAL] * 11


class TestEmojiContext:
    def test_only_selectors_and_joiners_qualify(self) -> None:
        text = f"{WARNING}\u200b"
        assert not is_emoji_context(text, 1)

    def test_index_at_either_end(self) -> None:
        assert not is_emoji_context(VS16, 0)
        assert not is_emoji_context(ZWJ, 0)
        assert is_emoji_context(f"{WARNING}{VS16}", 1)


class TestConfig:
    def test_default_is_on(self) -> None:
        assert load_config().allow_emoji is True

    def test_can_be_turned_off(self, tmp_path: Path) -> None:
        cfg = tmp_path / ".heckler.yml"
        cfg.write_text("allow_emoji: false  # flag every selector\n", encoding="utf-8")
        assert load_config(config_path=str(cfg)).allow_emoji is False
