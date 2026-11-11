"""Character database for dangerous invisible Unicode codepoints.

Covers: Glassworm (Variation Selectors), Trojan Source (bidi controls),
zero-width characters, tag characters, invisible operators, and more.
"""

from __future__ import annotations

import enum
import re


class ThreatCategory(enum.Enum):
    VARIATION_SELECTOR = "variation_selector"
    BIDI_CONTROL = "bidi_control"
    ZERO_WIDTH = "zero_width"
    TAG_CHARACTER = "tag_character"
    INVISIBLE_FORMAT = "invisible_format"
    INVISIBLE_IDENTIFIER = "invisible_identifier"


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
}

# Compiled regex covering all dangerous codepoint ranges
DANGEROUS_UNICODE_RE = re.compile(
    r'['
    r'\u00A0'           # No-Break Space
    r'\u00AD'           # Soft Hyphen
    r'\u034F'           # Combining Grapheme Joiner
    r'\u061C'           # Arabic Letter Mark
    r'\u115F-\u1160'    # Hangul Choseong/Jungseong Fillers
    r'\u1680'           # Ogham Space Mark
    r'\u17B4-\u17B5'    # Khmer Vowel Inherent
    r'\u180B-\u180E'    # Mongolian Free Variation Selectors + Vowel Separator
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
    r'\uFFF9-\uFFFC'    # Interlinear Annotation + Object Replacement
    r']'
    r'|[\U000E0001\U000E0020-\U000E007F]'  # Tag characters
    r'|[\U000E0100-\U000E01EF]'            # Variation Selectors Supplement (Glassworm secondary)
)


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
    return CharInfo(f"Unknown U+{cp:04X}", ThreatCategory.INVISIBLE_FORMAT, Severity.MEDIUM)


# Characters that can take an emoji or text presentation selector. This is a
# superset of the bases in Unicode's emoji-variation-sequences.txt (checked
# against 18.0), kept as block ranges so that new emoji need no update here.
# The ASCII keycap bases are separate: they only count when U+20E3 follows.
_EMOJI_BASE_RANGES: tuple[tuple[int, int], ...] = (
    (0x00A9, 0x00A9),    # Copyright
    (0x00AE, 0x00AE),    # Registered
    (0x203C, 0x203C),    # Double exclamation mark
    (0x2049, 0x2049),    # Exclamation question mark
    (0x2122, 0x2122),    # Trade mark
    (0x2139, 0x2139),    # Information source
    (0x2194, 0x21AA),    # Arrows
    (0x231A, 0x23FF),    # Watch, hourglass, keyboard, media controls
    (0x24C2, 0x24C2),    # Circled M
    (0x25AA, 0x25FE),    # Geometric shapes
    (0x2600, 0x27BF),    # Miscellaneous symbols and dingbats
    (0x2934, 0x2935),    # Curved arrows
    (0x2B05, 0x2B55),    # Arrows, squares, star, circle
    (0x3030, 0x3030),    # Wavy dash
    (0x303D, 0x303D),    # Part alternation mark
    (0x3297, 0x3297),    # Circled ideograph congratulation
    (0x3299, 0x3299),    # Circled ideograph secret
    (0x1F000, 0x1FAFF),  # Emoji blocks, including skin tone modifiers
)
_KEYCAP_BASES = frozenset("0123456789#*")
_COMBINING_ENCLOSING_KEYCAP = "\u20E3"
_PRESENTATION_SELECTORS = frozenset({0xFE0E, 0xFE0F})
_ZERO_WIDTH_JOINER = 0x200D


def _is_emoji_base(ch: str) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in _EMOJI_BASE_RANGES)


def _is_variation_selector(ch: str) -> bool:
    cp = ord(ch)
    return 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF or 0x180B <= cp <= 0x180D


def is_emoji_context(text: str, index: int) -> bool:
    """True if the character at *index* is an ordinary part of an emoji.

    Well-formed emoji contain two of the characters heckler flags:

    - U+FE0E and U+FE0F, the text and emoji presentation selectors, directly
      after the character they style (U+26A0 U+FE0F is the warning sign), or
      after a keycap base that U+20E3 then encloses. A selector that is
      followed by another variation selector never qualifies, so a run of
      them is reported in full.
    - U+200D, the zero width joiner, between two emoji, as in the family,
      profession and flag sequences.

    Glassworm hides its payload in long runs of selectors with nothing
    visible between them; one selector after a visible pictograph cannot
    carry that.
    """
    cp = ord(text[index])
    prev = text[index - 1] if index > 0 else ""
    nxt = text[index + 1] if index + 1 < len(text) else ""

    if cp in _PRESENTATION_SELECTORS:
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
