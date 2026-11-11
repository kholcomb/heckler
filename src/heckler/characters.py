"""Character database for dangerous invisible Unicode codepoints.

Covers: Glassworm (Variation Selectors), Trojan Source (bidi controls),
zero-width characters, tag characters, invisible operators, and more.

The detection set is every code point with the Unicode property
Default_Ignorable_Code_Point (renderers draw nothing for these, including
the ones that are still unassigned), every space and line separator other
than the ordinary space, the control characters other than TAB, LF and CR,
and a handful of glyphs that are defined to be blank.

Two groups of format characters (general category Cf) are left out on
purpose. Neither is default-ignorable, so a renderer without a glyph for
one is expected to draw its missing-glyph box rather than nothing:

- The Egyptian hieroglyph format controls, U+13430-1343F. They arrange
  the hieroglyphs on either side of them. They are not bidi controls, no
  identifier can hold one, and normalization leaves them in place, so
  they serve neither as a hidden alphabet nor to reorder or disguise code.
- The Arabic, Syriac and Kaithi number and abbreviation signs (U+0600-0605,
  U+06DD, U+070F, U+0890-0891, U+08E2, U+110BD, U+110CD), which are
  visible marks.

tests/test_unicode_data.py holds the detection set to the Unicode property
data and lists these exclusions, so a format character that a later
Unicode version adds has to be placed on one side or the other.
"""

from __future__ import annotations

import bisect
import enum
import re


class ThreatCategory(enum.Enum):
    VARIATION_SELECTOR = "variation_selector"
    BIDI_CONTROL = "bidi_control"
    ZERO_WIDTH = "zero_width"
    TAG_CHARACTER = "tag_character"
    INVISIBLE_FORMAT = "invisible_format"
    INVISIBLE_IDENTIFIER = "invisible_identifier"
    CONTROL_CHARACTER = "control_character"


class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = list(Severity)
        return order.index(self) <= order.index(other)

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = list(Severity)
        return order.index(self) < order.index(other)

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = list(Severity)
        return order.index(self) >= order.index(other)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = list(Severity)
        return order.index(self) > order.index(other)


class CharInfo:
    __slots__ = ("name", "category", "severity")

    def __init__(self, name: str, category: ThreatCategory, severity: Severity) -> None:
        self.name = name
        self.category = category
        self.severity = severity


# Hand-aligned data tables: keep the formatter out.
# fmt: off
# Known codepoints with explicit metadata
CHAR_DB: dict[int, CharInfo] = {
    # Zero-width characters (MEDIUM)
    0x200B: CharInfo("Zero Width Space", ThreatCategory.ZERO_WIDTH, Severity.MEDIUM),
    0x200C: CharInfo("Zero Width Non-Joiner", ThreatCategory.ZERO_WIDTH, Severity.MEDIUM),
    0x200D: CharInfo("Zero Width Joiner", ThreatCategory.ZERO_WIDTH, Severity.MEDIUM),
    0xFEFF: CharInfo("BOM / Zero Width No-Break Space", ThreatCategory.ZERO_WIDTH, Severity.MEDIUM),
    0x2060: CharInfo("Word Joiner", ThreatCategory.ZERO_WIDTH, Severity.MEDIUM),
    # Bidi controls (HIGH, RLO is CRITICAL)
    0x200E: CharInfo("Left-to-Right Mark", ThreatCategory.BIDI_CONTROL, Severity.HIGH),
    0x200F: CharInfo("Right-to-Left Mark", ThreatCategory.BIDI_CONTROL, Severity.HIGH),
    0x061C: CharInfo("Arabic Letter Mark", ThreatCategory.BIDI_CONTROL, Severity.HIGH),
    0x202A: CharInfo("Left-to-Right Embedding", ThreatCategory.BIDI_CONTROL, Severity.HIGH),
    0x202B: CharInfo("Right-to-Left Embedding", ThreatCategory.BIDI_CONTROL, Severity.HIGH),
    0x202C: CharInfo("Pop Directional Formatting", ThreatCategory.BIDI_CONTROL, Severity.HIGH),
    0x202D: CharInfo("Left-to-Right Override", ThreatCategory.BIDI_CONTROL, Severity.HIGH),
    0x202E: CharInfo("Right-to-Left Override", ThreatCategory.BIDI_CONTROL, Severity.CRITICAL),
    0x2066: CharInfo("Left-to-Right Isolate", ThreatCategory.BIDI_CONTROL, Severity.HIGH),
    0x2067: CharInfo("Right-to-Left Isolate", ThreatCategory.BIDI_CONTROL, Severity.HIGH),
    0x2068: CharInfo("First Strong Isolate", ThreatCategory.BIDI_CONTROL, Severity.HIGH),
    0x2069: CharInfo("Pop Directional Isolate", ThreatCategory.BIDI_CONTROL, Severity.HIGH),
    # Invisible format/operators (MEDIUM)
    0x00AD: CharInfo("Soft Hyphen", ThreatCategory.INVISIBLE_FORMAT, Severity.LOW),
    0x00A0: CharInfo("No-Break Space", ThreatCategory.INVISIBLE_FORMAT, Severity.LOW),
    0x180E: CharInfo("Mongolian Vowel Separator", ThreatCategory.INVISIBLE_FORMAT, Severity.LOW),
    0x2061: CharInfo("Function Application", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM),
    0x2062: CharInfo("Invisible Times", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM),
    0x2063: CharInfo("Invisible Separator", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM),
    0x2064: CharInfo("Invisible Plus", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM),
    0xFFF9: CharInfo(
        "Interlinear Annotation Anchor", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM,
    ),
    0xFFFA: CharInfo(
        "Interlinear Annotation Separator", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM,
    ),
    0xFFFB: CharInfo(
        "Interlinear Annotation Terminator", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM,
    ),
    # Deprecated format chars
    0x206A: CharInfo(
        "Inhibit Symmetric Swapping", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM,
    ),
    0x206B: CharInfo(
        "Activate Symmetric Swapping", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM,
    ),
    0x206C: CharInfo(
        "Inhibit Arabic Form Shaping", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM,
    ),
    0x206D: CharInfo(
        "Activate Arabic Form Shaping", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM,
    ),
    0x206E: CharInfo("National Digit Shapes", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM),
    0x206F: CharInfo("Nominal Digit Shapes", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM),
    # Invisible identifiers (MEDIUM)
    0x3164: CharInfo(
        "Hangul Filler", ThreatCategory.INVISIBLE_IDENTIFIER, Severity.MEDIUM,
    ),
    0xFFA0: CharInfo(
        "Halfwidth Hangul Filler", ThreatCategory.INVISIBLE_IDENTIFIER, Severity.MEDIUM,
    ),
    0x2800: CharInfo("Braille Pattern Blank", ThreatCategory.INVISIBLE_IDENTIFIER, Severity.MEDIUM),
    0x115F: CharInfo(
        "Hangul Choseong Filler", ThreatCategory.INVISIBLE_IDENTIFIER, Severity.MEDIUM,
    ),
    0x1160: CharInfo(
        "Hangul Jungseong Filler", ThreatCategory.INVISIBLE_IDENTIFIER, Severity.MEDIUM,
    ),
    # Additional invisible format chars
    0x034F: CharInfo("Combining Grapheme Joiner", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM),
    0x17B4: CharInfo("Khmer Vowel Inherent Aq", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM),
    0x17B5: CharInfo("Khmer Vowel Inherent Aa", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM),
    0x180B: CharInfo(
        "Mongolian Free Variation Selector One",
        ThreatCategory.VARIATION_SELECTOR, Severity.HIGH,
    ),
    0x180C: CharInfo(
        "Mongolian Free Variation Selector Two",
        ThreatCategory.VARIATION_SELECTOR, Severity.HIGH,
    ),
    0x180D: CharInfo(
        "Mongolian Free Variation Selector Three",
        ThreatCategory.VARIATION_SELECTOR, Severity.HIGH,
    ),
    0xFFFC: CharInfo(
        "Object Replacement Character", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM,
    ),
    # Exotic whitespace (LOW — visually similar to space but semantically different)
    0x1680: CharInfo("Ogham Space Mark", ThreatCategory.INVISIBLE_FORMAT, Severity.LOW),
    0x2000: CharInfo("En Quad", ThreatCategory.INVISIBLE_FORMAT, Severity.LOW),
    0x2001: CharInfo("Em Quad", ThreatCategory.INVISIBLE_FORMAT, Severity.LOW),
    0x2002: CharInfo("En Space", ThreatCategory.INVISIBLE_FORMAT, Severity.LOW),
    0x2003: CharInfo("Em Space", ThreatCategory.INVISIBLE_FORMAT, Severity.LOW),
    0x2004: CharInfo("Three-Per-Em Space", ThreatCategory.INVISIBLE_FORMAT, Severity.LOW),
    0x2005: CharInfo("Four-Per-Em Space", ThreatCategory.INVISIBLE_FORMAT, Severity.LOW),
    0x2006: CharInfo("Six-Per-Em Space", ThreatCategory.INVISIBLE_FORMAT, Severity.LOW),
    0x2007: CharInfo("Figure Space", ThreatCategory.INVISIBLE_FORMAT, Severity.LOW),
    0x2008: CharInfo("Punctuation Space", ThreatCategory.INVISIBLE_FORMAT, Severity.LOW),
    0x2009: CharInfo("Thin Space", ThreatCategory.INVISIBLE_FORMAT, Severity.LOW),
    0x200A: CharInfo("Hair Space", ThreatCategory.INVISIBLE_FORMAT, Severity.LOW),
    0x2028: CharInfo("Line Separator", ThreatCategory.BIDI_CONTROL, Severity.HIGH),
    0x2029: CharInfo("Paragraph Separator", ThreatCategory.BIDI_CONTROL, Severity.HIGH),
    0x202F: CharInfo("Narrow No-Break Space", ThreatCategory.INVISIBLE_FORMAT, Severity.LOW),
    0x205F: CharInfo("Medium Mathematical Space", ThreatCategory.INVISIBLE_FORMAT, Severity.LOW),
    0x3000: CharInfo("Ideographic Space", ThreatCategory.INVISIBLE_FORMAT, Severity.LOW),
    # Control characters. Escape starts terminal sequences that can hide or
    # rewrite what a terminal shows; Backspace and Delete can erase it. A NUL
    # makes git and review tools treat the file as binary and hide its diff;
    # the scanner reports it once per file. Form Feed is a page break in a
    # lot of C, Python and Emacs Lisp source, so it is only listed at INFO.
    # The remaining controls are named in get_char_info().
    0x0000: CharInfo("Null", ThreatCategory.CONTROL_CHARACTER, Severity.MEDIUM),
    0x0008: CharInfo("Backspace", ThreatCategory.CONTROL_CHARACTER, Severity.MEDIUM),
    0x000B: CharInfo("Line Tabulation", ThreatCategory.CONTROL_CHARACTER, Severity.LOW),
    0x000C: CharInfo("Form Feed", ThreatCategory.CONTROL_CHARACTER, Severity.INFO),
    0x001B: CharInfo("Escape", ThreatCategory.CONTROL_CHARACTER, Severity.HIGH),
    0x007F: CharInfo("Delete", ThreatCategory.CONTROL_CHARACTER, Severity.MEDIUM),
    0x0085: CharInfo("Next Line", ThreatCategory.CONTROL_CHARACTER, Severity.MEDIUM),
    0x180F: CharInfo(
        "Mongolian Free Variation Selector Four",
        ThreatCategory.VARIATION_SELECTOR, Severity.HIGH,
    ),
    # Invisible format controls outside the BMP
    0x1BCA0: CharInfo(
        "Shorthand Format Letter Overlap", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM,
    ),
    0x1BCA1: CharInfo(
        "Shorthand Format Continuing Overlap", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM,
    ),
    0x1BCA2: CharInfo(
        "Shorthand Format Down Step", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM,
    ),
    0x1BCA3: CharInfo("Shorthand Format Up Step", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM),
    0x1D173: CharInfo(
        "Musical Symbol Begin Beam", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM,
    ),
    0x1D174: CharInfo("Musical Symbol End Beam", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM),
    0x1D175: CharInfo("Musical Symbol Begin Tie", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM),
    0x1D176: CharInfo("Musical Symbol End Tie", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM),
    0x1D177: CharInfo(
        "Musical Symbol Begin Slur", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM,
    ),
    0x1D178: CharInfo("Musical Symbol End Slur", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM),
    0x1D179: CharInfo(
        "Musical Symbol Begin Phrase", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM,
    ),
    0x1D17A: CharInfo(
        "Musical Symbol End Phrase", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM,
    ),
    # Glyphs that are defined to be blank. The first three are letters or
    # marks, so they can appear in identifiers.
    0x13441: CharInfo(
        "Egyptian Hieroglyph Full Blank", ThreatCategory.INVISIBLE_IDENTIFIER, Severity.MEDIUM,
    ),
    0x13442: CharInfo(
        "Egyptian Hieroglyph Half Blank", ThreatCategory.INVISIBLE_IDENTIFIER, Severity.MEDIUM,
    ),
    0x16FE4: CharInfo(
        "Khitan Small Script Filler", ThreatCategory.INVISIBLE_IDENTIFIER, Severity.MEDIUM,
    ),
    0x1D159: CharInfo(
        "Musical Symbol Null Notehead", ThreatCategory.INVISIBLE_FORMAT, Severity.LOW,
    ),
}

# Compiled regex covering all dangerous codepoint ranges
DANGEROUS_UNICODE_RE = re.compile(
    r'['
    r'\x00-\x08'        # C0 controls before TAB
    r'\x0B\x0C'         # Line Tabulation, Form Feed
    r'\x0E-\x1F'        # C0 controls after CR, including Escape
    r'\x7F-\x9F'        # Delete and the C1 controls
    r'\u00A0'           # No-Break Space
    r'\u00AD'           # Soft Hyphen
    r'\u034F'           # Combining Grapheme Joiner
    r'\u061C'           # Arabic Letter Mark
    r'\u115F-\u1160'    # Hangul Choseong/Jungseong Fillers
    r'\u1680'           # Ogham Space Mark
    r'\u17B4-\u17B5'    # Khmer Vowel Inherent
    r'\u180B-\u180F'    # Mongolian Free Variation Selectors 1-4 + Vowel Separator
    r'\u2000-\u200F'    # Typographic spaces + ZWSP/ZWNJ/ZWJ/LRM/RLM
    r'\u2028-\u202F'    # Line/Para seps + Bidi embeddings/overrides + NNBSP
    r'\u205F'           # Medium Mathematical Space
    r'\u2060-\u206F'    # Word Joiner, invisible operators, bidi isolates, deprecated format chars
    r'\u2800'           # Braille Pattern Blank
    r'\u3000'           # Ideographic Space
    r'\u3164'           # Hangul Filler
    r'\uFE00-\uFE0F'   # Variation Selectors 1-16 (Glassworm primary)
    r'\uFEFF'           # BOM / ZWNBSP
    r'\uFFA0'           # Halfwidth Hangul Filler
    r'\uFFF0-\uFFFC'    # Reserved default-ignorables, Interlinear Annotation, Object Replacement
    r']'
    r'|[\U00013441\U00013442\U00016FE4]'    # Egyptian Hieroglyph blanks, Khitan filler
    r'|[\U0001BCA0-\U0001BCA3]'            # Shorthand format controls
    r'|[\U0001D159\U0001D173-\U0001D17A]'  # Musical null notehead and format controls
    # The whole default-ignorable block of plane 14: the tag characters, the
    # Variation Selectors Supplement (Glassworm secondary), and the reserved
    # code points around them, which are just as invisible.
    r'|[\U000E0000-\U000E0FFF]'
)
# fmt: on


def get_char_info(cp: int) -> CharInfo:
    """Get character info for a codepoint. Handles both known and dynamic ranges."""
    if cp in CHAR_DB:
        return CHAR_DB[cp]
    if 0xFE00 <= cp <= 0xFE0F:
        return CharInfo(
            f"Variation Selector {cp - 0xFE00 + 1}",
            ThreatCategory.VARIATION_SELECTOR,
            Severity.CRITICAL,
        )
    if 0xE0100 <= cp <= 0xE01EF:
        return CharInfo(
            f"Variation Selector {cp - 0xE0100 + 17}",
            ThreatCategory.VARIATION_SELECTOR,
            Severity.CRITICAL,
        )
    if cp == 0xE0001:
        return CharInfo("Language Tag", ThreatCategory.TAG_CHARACTER, Severity.HIGH)
    if 0xE0020 <= cp <= 0xE007F:
        ascii_val = cp - 0xE0000
        return CharInfo(
            f"Tag {chr(ascii_val)!r}" if 0x21 <= ascii_val <= 0x7E else "Tag Space",
            ThreatCategory.TAG_CHARACTER,
            Severity.HIGH,
        )
    if cp < 0x20 or 0x7F <= cp <= 0x9F:
        return CharInfo(
            f"Control Character U+{cp:04X}", ThreatCategory.CONTROL_CHARACTER, Severity.MEDIUM
        )
    if cp == 0x2065 or 0xFFF0 <= cp <= 0xFFF8 or 0xE0000 <= cp <= 0xE0FFF:
        # Not assigned to any character, yet renderers are told to draw
        # nothing for them. Nothing legitimate puts one in a source file.
        return CharInfo(
            "Reserved Default Ignorable Code Point", ThreatCategory.INVISIBLE_FORMAT, Severity.HIGH
        )
    return CharInfo(f"Unknown U+{cp:04X}", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM)


# Characters that can take an emoji or text presentation selector, or stand
# on either side of a joiner: every code point with the Unicode property
# Emoji or Extended_Pictographic. The ASCII keycap bases are separate: they
# only count when U+20E3 follows. Extended_Pictographic takes in the code
# points Unicode keeps free for future emoji, so a new emoji seldom needs a
# change here. tests/test_unicode_data.py derives this table from the
# property data and prints the new one when the two differ.
# fmt: off
_EMOJI_BASE_RANGES: tuple[tuple[int, int], ...] = (
    (0x00A9, 0x00A9), (0x00AE, 0x00AE), (0x203C, 0x203C), (0x2049, 0x2049),
    (0x2122, 0x2122), (0x2139, 0x2139), (0x2194, 0x2199), (0x21A9, 0x21AA),
    (0x231A, 0x231B), (0x2328, 0x2328), (0x23CF, 0x23CF), (0x23E9, 0x23F3),
    (0x23F8, 0x23FA), (0x24C2, 0x24C2), (0x25AA, 0x25AB), (0x25B6, 0x25B6),
    (0x25C0, 0x25C0), (0x25FB, 0x25FE), (0x2600, 0x2604), (0x260E, 0x260E),
    (0x2611, 0x2611), (0x2614, 0x2615), (0x2618, 0x2618), (0x261D, 0x261D),
    (0x2620, 0x2620), (0x2622, 0x2623), (0x2626, 0x2626), (0x262A, 0x262A),
    (0x262E, 0x262F), (0x2638, 0x263A), (0x2640, 0x2640), (0x2642, 0x2642),
    (0x2648, 0x2653), (0x265F, 0x2660), (0x2663, 0x2663), (0x2665, 0x2666),
    (0x2668, 0x2668), (0x267B, 0x267B), (0x267E, 0x267F), (0x2692, 0x2697),
    (0x2699, 0x2699), (0x269B, 0x269C), (0x26A0, 0x26A1), (0x26A7, 0x26A7),
    (0x26AA, 0x26AB), (0x26B0, 0x26B1), (0x26BD, 0x26BE), (0x26C4, 0x26C5),
    (0x26C8, 0x26C8), (0x26CE, 0x26CF), (0x26D1, 0x26D1), (0x26D3, 0x26D4),
    (0x26E9, 0x26EA), (0x26F0, 0x26F5), (0x26F7, 0x26FA), (0x26FD, 0x26FD),
    (0x2702, 0x2702), (0x2705, 0x2705), (0x2708, 0x270D), (0x270F, 0x270F),
    (0x2712, 0x2712), (0x2714, 0x2714), (0x2716, 0x2716), (0x271D, 0x271D),
    (0x2721, 0x2721), (0x2728, 0x2728), (0x2733, 0x2734), (0x2744, 0x2744),
    (0x2747, 0x2747), (0x274C, 0x274C), (0x274E, 0x274E), (0x2753, 0x2755),
    (0x2757, 0x2757), (0x2763, 0x2764), (0x2795, 0x2797), (0x27A1, 0x27A1),
    (0x27B0, 0x27B0), (0x27BF, 0x27BF), (0x2934, 0x2935), (0x2B05, 0x2B07),
    (0x2B1B, 0x2B1C), (0x2B50, 0x2B50), (0x2B55, 0x2B55), (0x3030, 0x3030),
    (0x303D, 0x303D), (0x3297, 0x3297), (0x3299, 0x3299), (0x1F004, 0x1F004),
    (0x1F02C, 0x1F02F), (0x1F094, 0x1F09F), (0x1F0AF, 0x1F0B0), (0x1F0C0, 0x1F0C0),
    (0x1F0CF, 0x1F0D0), (0x1F0F6, 0x1F0FF), (0x1F170, 0x1F171), (0x1F17E, 0x1F17F),
    (0x1F18E, 0x1F18E), (0x1F191, 0x1F19A), (0x1F1AE, 0x1F1FF), (0x1F201, 0x1F20F),
    (0x1F21A, 0x1F21A), (0x1F22F, 0x1F22F), (0x1F232, 0x1F23A), (0x1F23C, 0x1F23F),
    (0x1F249, 0x1F25F), (0x1F266, 0x1F321), (0x1F324, 0x1F393), (0x1F396, 0x1F397),
    (0x1F399, 0x1F39B), (0x1F39E, 0x1F3F0), (0x1F3F3, 0x1F3F5), (0x1F3F7, 0x1F4FD),
    (0x1F4FF, 0x1F53D), (0x1F549, 0x1F54E), (0x1F550, 0x1F567), (0x1F56F, 0x1F570),
    (0x1F573, 0x1F57A), (0x1F587, 0x1F587), (0x1F58A, 0x1F58D), (0x1F590, 0x1F590),
    (0x1F595, 0x1F596), (0x1F5A4, 0x1F5A5), (0x1F5A8, 0x1F5A8), (0x1F5B1, 0x1F5B2),
    (0x1F5BC, 0x1F5BC), (0x1F5C2, 0x1F5C4), (0x1F5D1, 0x1F5D3), (0x1F5DC, 0x1F5DE),
    (0x1F5E1, 0x1F5E1), (0x1F5E3, 0x1F5E3), (0x1F5E8, 0x1F5E8), (0x1F5EF, 0x1F5EF),
    (0x1F5F3, 0x1F5F3), (0x1F5FA, 0x1F64F), (0x1F680, 0x1F6C5), (0x1F6CB, 0x1F6D2),
    (0x1F6D5, 0x1F6E5), (0x1F6E9, 0x1F6E9), (0x1F6EB, 0x1F6F0), (0x1F6F3, 0x1F6FF),
    (0x1F7DA, 0x1F7FF), (0x1F80C, 0x1F80F), (0x1F848, 0x1F84F), (0x1F85A, 0x1F85F),
    (0x1F888, 0x1F88F), (0x1F8AE, 0x1F8AF), (0x1F8BC, 0x1F8BF), (0x1F8C2, 0x1F8CF),
    (0x1F8D9, 0x1F8FF), (0x1F90C, 0x1F93A), (0x1F93C, 0x1F945), (0x1F947, 0x1F9FF),
    (0x1FA58, 0x1FA5F), (0x1FA6E, 0x1FAFF), (0x1FC00, 0x1FFFD),
)
# fmt: on
_EMOJI_BASE_STARTS = tuple(lo for lo, _ in _EMOJI_BASE_RANGES)
_KEYCAP_BASES = frozenset("0123456789#*")
_COMBINING_ENCLOSING_KEYCAP = "\u20e3"
PRESENTATION_SELECTORS = frozenset({0xFE0E, 0xFE0F})
_ZERO_WIDTH_JOINER = 0x200D

# The flags of England, Scotland and Wales: a black flag, the region code
# spelled in tag characters, and a cancel tag. Unicode's emoji-sequences.txt
# lists these three and no other tag sequence as recommended for general
# interchange, so nothing else that is built from tags counts as an emoji.
_BLACK_FLAG = "\U0001f3f4"
_CANCEL_TAG = 0xE007F
_SUBDIVISION_FLAGS = frozenset(
    _BLACK_FLAG + "".join(chr(0xE0000 + ord(ch)) for ch in region) + chr(_CANCEL_TAG)
    for region in ("gbeng", "gbsct", "gbwls")
)
_SUBDIVISION_FLAG_LENGTH = 7


def _is_emoji_base(ch: str) -> bool:
    cp = ord(ch)
    i = bisect.bisect_right(_EMOJI_BASE_STARTS, cp) - 1
    return i >= 0 and cp <= _EMOJI_BASE_RANGES[i][1]


def _is_variation_selector(ch: str) -> bool:
    cp = ord(ch)
    return (
        0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF or 0x180B <= cp <= 0x180D or cp == 0x180F
    )


def is_emoji_context(text: str, index: int) -> bool:
    """True if the character at *index* is an ordinary part of an emoji.

    Well-formed emoji contain three of the kinds of character heckler flags:

    - U+FE0E and U+FE0F, the text and emoji presentation selectors, directly
      after the character they style (U+26A0 U+FE0F is the warning sign), or
      after a keycap base that U+20E3 then encloses. A selector that is
      followed by another variation selector never qualifies, so a run of
      them is reported in full.
    - U+200D, the zero width joiner, between two emoji, as in the family,
      profession and flag sequences.
    - Tag characters, in the flags of England, Scotland and Wales and nowhere
      else. A tag qualifies only as part of one of those three sequences,
      complete and directly after U+1F3F4; any other run of tags, including
      one that follows such a flag, is reported in full.

    Glassworm hides its payload in long runs of selectors with nothing
    visible between them; one selector after a visible pictograph cannot
    carry that.
    """
    cp = ord(text[index])
    prev = text[index - 1] if index > 0 else ""
    nxt = text[index + 1] if index + 1 < len(text) else ""

    if 0xE0020 <= cp <= _CANCEL_TAG:
        # The flag, if there is one, starts at most six characters back.
        for start in range(index - 1, max(index - _SUBDIVISION_FLAG_LENGTH, -1), -1):
            if text[start] == _BLACK_FLAG:
                return text[start : start + _SUBDIVISION_FLAG_LENGTH] in _SUBDIVISION_FLAGS
        return False

    if cp in PRESENTATION_SELECTORS:
        if nxt and _is_variation_selector(nxt):
            return False
        if prev in _KEYCAP_BASES:
            return nxt == _COMBINING_ENCLOSING_KEYCAP
        return bool(prev) and _is_emoji_base(prev)

    if cp == _ZERO_WIDTH_JOINER:
        if not nxt or not _is_emoji_base(nxt):
            return False
        if prev and ord(prev) == 0xFE0F:
            # Joiner after a styled emoji: look at what the selector styles.
            prev = text[index - 2] if index > 1 else ""
        return bool(prev) and _is_emoji_base(prev)

    return False
