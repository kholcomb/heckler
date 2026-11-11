"""The character tables, held to the Unicode property data.

characters.py is a static table, so that a scan gives the same result on
every interpreter. The standard library cannot check it: unicodedata has no
Default_Ignorable_Code_Point and no emoji properties, and its data is that
of whichever Unicode version the interpreter was built with. The regex
module carries the properties. It is installed for the tests only.

A regex release with a newer Unicode version can fail these tests with no
change in heckler. That is what they are for: the failure names the code
points that have to be placed, in the table or among the exclusions.
"""

from __future__ import annotations

import itertools
import unicodedata

import regex

from heckler.characters import (
    _EMOJI_BASE_RANGES,
    _KEYCAP_BASES,
    DANGEROUS_UNICODE_RE,
    _is_emoji_base,
)

# Every code point but the surrogates, which are not characters.
EVERYTHING = "".join(chr(cp) for cp in range(0x110000) if not 0xD800 <= cp <= 0xDFFF)


def _having(pattern: str) -> set[int]:
    """The code points that a pattern of regex-module properties matches."""
    return {ord(ch) for ch in regex.findall(pattern, EVERYTHING)}


def _spans(code_points: set[int]) -> list[tuple[int, int]]:
    """Sorted, as runs of consecutive code points."""
    spans: list[tuple[int, int]] = []
    for cp in sorted(code_points):
        if spans and cp == spans[-1][1] + 1:
            spans[-1] = (spans[-1][0], cp)
        else:
            spans.append((cp, cp))
    return spans


def _shown(code_points: set[int]) -> str:
    """For an assertion message: ``U+0600-0605 U+06DD``."""
    return " ".join(
        f"U+{lo:04X}" if lo == hi else f"U+{lo:04X}-{hi:04X}" for lo, hi in _spans(code_points)
    )


FLAGGED = {ord(ch) for ch in DANGEROUS_UNICODE_RE.findall(EVERYTHING)}

# What Unicode says is drawn as nothing or as a gap: the default-ignorable
# code points, the spaces and separators other than the ordinary space, and
# the control characters other than tab, LF and CR.
INVISIBLE = (
    _having(r"\p{Default_Ignorable_Code_Point}")
    | (_having(r"[\p{Zs}\p{Zl}\p{Zp}]") - {0x20})
    | (_having(r"\p{Cc}") - {0x09, 0x0A, 0x0D})
)

# Flagged although no property above covers them: glyphs that are defined
# to be blank, the interlinear annotation marks and the object replacement
# character.
BLANK_OR_PLACEHOLDER = {0x2800, 0xFFF9, 0xFFFA, 0xFFFB, 0xFFFC, 0x13441, 0x13442, 0x16FE4, 0x1D159}

# Format characters that are not flagged, on purpose. The docstring of
# characters.py and the README say why.
HIEROGLYPH_FORMAT_CONTROLS = set(range(0x13430, 0x13440))
NUMBER_AND_ABBREVIATION_SIGNS = {
    *range(0x0600, 0x0606),
    0x06DD,
    0x070F,
    0x0890,
    0x0891,
    0x08E2,
    0x110BD,
    0x110CD,
}
LEFT_OUT = HIEROGLYPH_FORMAT_CONTROLS | NUMBER_AND_ABBREVIATION_SIGNS


class TestDetectionSet:
    def test_everything_invisible_is_flagged(self) -> None:
        assert _shown(INVISIBLE - FLAGGED) == ""

    def test_nothing_else_is_flagged_but_the_blank_glyphs(self) -> None:
        assert _shown(FLAGGED - INVISIBLE) == _shown(BLANK_OR_PLACEHOLDER)

    def test_every_bidi_control_and_variation_selector_is_flagged(self) -> None:
        assert _shown(_having(r"[\p{Bidi_Control}\p{Variation_Selector}]") - FLAGGED) == ""


class TestFormatCharactersLeftOut:
    """A format character is flagged or listed here. Nothing is left out by oversight."""

    def test_the_ones_left_out_are_the_ones_listed(self) -> None:
        assert _shown(_having(r"\p{Cf}") - FLAGGED) == _shown(LEFT_OUT)

    def test_none_has_a_property_that_an_attack_needs(self) -> None:
        """Drawn as nothing, able to reorder text, part of an identifier, or a space."""
        useful = _having(
            r"[\p{Default_Ignorable_Code_Point}\p{Bidi_Control}\p{Join_Control}"
            r"\p{XID_Continue}\p{White_Space}\p{Pattern_White_Space}]"
        )
        assert _shown(LEFT_OUT & useful) == ""

    def test_normalization_does_not_remove_one(self) -> None:
        """So none can make two strings that compare equal after NFKC look different before."""
        changed = {cp for cp in LEFT_OUT if unicodedata.normalize("NFKC", chr(cp)) != chr(cp)}
        assert _shown(changed) == ""

    def test_the_signs_are_the_visible_marks_unicode_says_they_are(self) -> None:
        marks = _having(r"\p{Prepended_Concatenation_Mark}")
        assert _shown(NUMBER_AND_ABBREVIATION_SIGNS - marks) == ""


def _as_table(spans: list[tuple[int, int]]) -> str:
    """The spans as the rows of ``_EMOJI_BASE_RANGES``, to paste into characters.py."""
    cells = [f"(0x{lo:04X}, 0x{hi:04X})," for lo, hi in spans]
    return "\n".join("    " + " ".join(cells[i : i + 4]) for i in range(0, len(cells), 4))


class TestEmojiBases:
    def test_table_is_the_emoji_properties(self) -> None:
        """Emoji, and what Unicode keeps free for future emoji; the keycap bases are separate."""
        emoji = _having(r"[\p{Emoji}\p{Extended_Pictographic}]")
        expected = _spans({cp for cp in emoji if chr(cp) not in _KEYCAP_BASES})
        assert list(_EMOJI_BASE_RANGES) == expected, (
            "characters._EMOJI_BASE_RANGES should be:\n" + _as_table(expected)
        )

    def test_lookup_agrees_with_the_table(self) -> None:
        in_table = {cp for lo, hi in _EMOJI_BASE_RANGES for cp in range(lo, hi + 1)}
        assert {ord(ch) for ch in EVERYTHING if _is_emoji_base(ch)} == in_table

    def test_table_is_sorted_and_disjoint(self) -> None:
        flat = [cp for span in _EMOJI_BASE_RANGES for cp in span]
        assert flat == sorted(flat)
        assert all(
            later[0] > earlier[1] + 1 for earlier, later in itertools.pairwise(_EMOJI_BASE_RANGES)
        )
