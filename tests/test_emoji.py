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

WARNING = "\u26A0"          # takes U+FE0F to render as an emoji
HEART = "\u2764"
FLAG = "\U0001F3F3"
WOMAN = "\U0001F469"
LAPTOP = "\U0001F4BB"
FIRE = "\U0001F525"
SKIN_TONE = "\U0001F3FD"
VS15, VS16 = "\uFE0E", "\uFE0F"
ZWJ = "\u200D"
KEYCAP = "\u20E3"

WELL_FORMED = [
    pytest.param(f"# {WARNING}{VS16} Warning", id="emoji-presentation"),
    pytest.param(f"# {WARNING}{VS15} Warning", id="text-presentation"),
    pytest.param(f'x = "{FLAG}{VS16}"', id="supplementary-plane-base"),
    pytest.param(f"1{VS16}{KEYCAP} first", id="keycap"),
    pytest.param(f"#{VS16}{KEYCAP}", id="keycap-number-sign"),
    pytest.param(f"{WOMAN}{ZWJ}{LAPTOP}", id="zwj-profession"),
    pytest.param(f"{WOMAN}{SKIN_TONE}{ZWJ}{LAPTOP}", id="zwj-with-skin-tone"),
    pytest.param(f"{HEART}{VS16}{ZWJ}{FIRE}", id="zwj-after-selector"),
    pytest.param(f"{FLAG}{VS16}{ZWJ}\U0001F308", id="rainbow-flag"),
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
    @pytest.mark.parametrize(("text", "expected"), [
        pytest.param(f'x = "{VS16}"', [Severity.CRITICAL], id="selector-after-punctuation"),
        pytest.param(f"a{VS16}", [Severity.CRITICAL], id="selector-after-letter"),
        pytest.param(VS16, [Severity.CRITICAL], id="selector-at-line-start"),
        pytest.param(f"1{VS16}", [Severity.CRITICAL], id="digit-without-keycap"),
        pytest.param(f"{WARNING}\uFE00", [Severity.CRITICAL], id="other-selector-after-emoji"),
        pytest.param(
            f"{WARNING}{VS16}{VS16}", [Severity.CRITICAL] * 2, id="run-of-two",
        ),
        pytest.param(
            f"{WARNING}{VS16}\uFE01\uFE02", [Severity.CRITICAL] * 3, id="payload-behind-an-emoji",
        ),
        pytest.param(
            f"{WARNING}{VS16}\U000E0100", [Severity.CRITICAL] * 2, id="supplement-run",
        ),
        pytest.param(f"ad{ZWJ}min", [Severity.MEDIUM], id="joiner-between-letters"),
        pytest.param(f"{WOMAN}{ZWJ}x", [Severity.MEDIUM], id="joiner-before-letter"),
        pytest.param(f"x{ZWJ}{LAPTOP}", [Severity.MEDIUM], id="joiner-after-letter"),
        pytest.param(f"{WOMAN}{ZWJ}", [Severity.MEDIUM], id="joiner-at-line-end"),
        pytest.param(
            f"a{VS16}{ZWJ}{FIRE}", [Severity.CRITICAL, Severity.MEDIUM],
            id="joiner-after-misplaced-selector",
        ),
        pytest.param(f"{WARNING}\u200B", [Severity.MEDIUM], id="zero-width-space-after-emoji"),
    ])
    def test_reported(self, text: str, expected: list[Severity]) -> None:
        assert [f.severity for f in Scanner().scan_text(text)] == expected

    def test_allow_emoji_off_restores_strict_behaviour(self) -> None:
        findings = Scanner(allow_emoji=False).scan_text(f"# {WARNING}{VS16} Warning")
        assert [f.severity for f in findings] == [Severity.CRITICAL]

    def test_dependency_code_gets_the_same_rule(self) -> None:
        text = f'log("{WARNING}{VS16}"); x = `\uFE01\uFE02`;'
        findings = Scanner(scan_deps=True).scan_text(text, "node_modules/pkg/index.js")
        assert [f.codepoint for f in findings] == [0xFE01, 0xFE02]


class TestEmojiContext:
    def test_only_selectors_and_joiners_qualify(self) -> None:
        text = f"{WARNING}\u200B"
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
