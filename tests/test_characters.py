"""Tests for the character database and regex pattern."""

from __future__ import annotations

from heckler.characters import (
    DANGEROUS_UNICODE_RE,
    Severity,
    ThreatCategory,
    get_char_info,
)


class TestDangerousUnicodeRegex:
    """Verify the regex matches every dangerous codepoint from the report."""

    def _assert_matches(self, codepoint: int) -> None:
        char = chr(codepoint)
        assert DANGEROUS_UNICODE_RE.search(char), f"U+{codepoint:04X} should match"

    def _assert_no_match(self, codepoint: int) -> None:
        char = chr(codepoint)
        assert not DANGEROUS_UNICODE_RE.search(char), f"U+{codepoint:04X} should NOT match"

    def test_zero_width_chars(self) -> None:
        for cp in [0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060]:
            self._assert_matches(cp)

    def test_bidi_controls(self) -> None:
        for cp in range(0x202A, 0x202F):
            self._assert_matches(cp)
        for cp in range(0x2066, 0x206A):
            self._assert_matches(cp)
        self._assert_matches(0x200E)
        self._assert_matches(0x200F)
        self._assert_matches(0x061C)

    def test_variation_selectors_primary(self) -> None:
        for cp in range(0xFE00, 0xFE10):
            self._assert_matches(cp)

    def test_variation_selectors_supplement(self) -> None:
        for cp in [0xE0100, 0xE0101, 0xE01EF]:
            self._assert_matches(cp)

    def test_tag_characters(self) -> None:
        self._assert_matches(0xE0001)
        for cp in [0xE0020, 0xE0041, 0xE007F]:
            self._assert_matches(cp)

    def test_invisible_format(self) -> None:
        for cp in [0x00AD, 0x00A0, 0x180E, 0x2061, 0x2062, 0x2063, 0x2064]:
            self._assert_matches(cp)

    def test_invisible_identifiers(self) -> None:
        for cp in [0x3164, 0xFFA0, 0x2800]:
            self._assert_matches(cp)

    def test_deprecated_format(self) -> None:
        for cp in range(0x206A, 0x2070):
            self._assert_matches(cp)

    def test_interlinear_annotation(self) -> None:
        for cp in [0xFFF9, 0xFFFA, 0xFFFB]:
            self._assert_matches(cp)

    def test_safe_ascii_does_not_match(self) -> None:
        for cp in range(0x20, 0x7F):
            self._assert_no_match(cp)

    def test_common_unicode_does_not_match(self) -> None:
        # Common non-ASCII that should NOT trigger
        for char in 'éèêëñüöäß中文日本語한국어':
            assert not DANGEROUS_UNICODE_RE.search(char), f"'{char}' should not match"


class TestGetCharInfo:
    def test_known_codepoint(self) -> None:
        info = get_char_info(0x200B)
        assert info.name == "Zero Width Space"
        assert info.category == ThreatCategory.ZERO_WIDTH
        assert info.severity == Severity.MEDIUM

    def test_rlo_is_critical(self) -> None:
        info = get_char_info(0x202E)
        assert info.severity == Severity.CRITICAL

    def test_variation_selector_primary(self) -> None:
        info = get_char_info(0xFE01)
        assert "Variation Selector 2" in info.name
        assert info.category == ThreatCategory.VARIATION_SELECTOR
        assert info.severity == Severity.CRITICAL

    def test_variation_selector_supplement(self) -> None:
        info = get_char_info(0xE0100)
        assert "Variation Selector" in info.name
        assert info.severity == Severity.CRITICAL

    def test_tag_character(self) -> None:
        info = get_char_info(0xE0041)
        assert "Tag" in info.name
        assert info.category == ThreatCategory.TAG_CHARACTER
        assert info.severity == Severity.HIGH

    def test_language_tag(self) -> None:
        info = get_char_info(0xE0001)
        assert info.name == "Language Tag"


class TestSeverityOrdering:
    def test_critical_is_highest(self) -> None:
        assert Severity.CRITICAL >= Severity.HIGH
        assert Severity.CRITICAL >= Severity.LOW

    def test_low_is_lower_than_high(self) -> None:
        assert Severity.LOW < Severity.HIGH
        assert Severity.LOW <= Severity.MEDIUM
