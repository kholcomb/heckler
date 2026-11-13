"""Core scanner for detecting dangerous invisible Unicode characters."""

from __future__ import annotations

import codecs
import functools
import os
import re
import stat
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from pathlib import Path

from ._output import write_err
from .characters import (
    DANGEROUS_NON_CONTROL_RE,
    DANGEROUS_UNICODE_RE,
    KEYCAP_BASES,
    PRESENTATION_SELECTORS,
    ZERO_WIDTH_JOINER,
    CharInfo,
    Severity,
    ThreatCategory,
    get_char_info,
    is_emoji_context,
)


@dataclass
class Finding:
    file: str
    line: int
    column: int
    codepoint: int
    codepoint_hex: str
    char_name: str
    category: ThreatCategory
    severity: Severity
    line_content: str
    source: str = "project"  # "project" or "dependency"
    package: str | None = None

    @classmethod
    def from_match(
        cls,
        filepath: str,
        line_num: int,
        col: int,
        cp: int,
        info: CharInfo,
        line_content: str,
        source: str = "project",
        package: str | None = None,
    ) -> Finding:
        return cls(
            file=filepath,
            line=line_num,
            column=col,
            codepoint=cp,
            codepoint_hex=f"U+{cp:04X}",
            char_name=info.name,
            category=info.category,
            severity=info.severity,
            line_content=line_content,
            source=source,
            package=package,
        )


# Names that mark a file as source. A directory walk scans such a file
# whatever its bytes are, and any other file when its content is text. The
# lists are a floor under that content check, not a filter, so they say
# nothing about what heckler can scan and are not documented as if they did.
#
# Hand-aligned data tables: keep the formatter out.
# fmt: off
DEFAULT_TEXT_EXTENSIONS = frozenset({
    # Core web / scripting
    '.js', '.cjs', '.mjs', '.ts', '.mts', '.cts', '.jsx', '.tsx', '.py', '.pyi',
    '.pth', '.rb', '.go', '.rs', '.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp',
    '.hxx', '.java', '.cs', '.php', '.sh', '.bash', '.zsh', '.yaml', '.yml',
    '.json', '.jsonc', '.json5', '.toml', '.xml', '.html', '.htm', '.css', '.scss',
    '.sass', '.less', '.sql', '.swift', '.kt', '.kts', '.scala', '.lua', '.pl',
    '.r', '.md', '.rst', '.adoc', '.txt', '.cfg', '.ini', '.dockerfile', '.tf',
    '.hcl', '.vue', '.svelte', '.ipynb',
    '.pyx', '.pxd', '.pxi',                       # Cython
    # Shells
    '.ps1', '.bat', '.cmd', '.fish',
    # Templates
    '.ejs', '.erb', '.hbs', '.njk', '.pug', '.jinja', '.jinja2', '.j2',
    # Instructions for coding agents
    '.mdc',
    # Build systems
    '.gradle', '.rake', '.cmake', '.mk',
    # Schema/IDL
    '.graphql', '.gql', '.proto',
    # Config ('.env' and '.env.*' are matched by name, below)
    '.conf', '.properties',
    # Modern / additional languages
    '.dart',                                      # Dart / Flutter
    '.ex', '.exs',                                # Elixir
    '.erl', '.hrl',                               # Erlang
    '.zig',                                        # Zig
    '.nim',                                        # Nim
    '.ml', '.mli',                                 # OCaml
    '.hs', '.lhs',                                 # Haskell
    '.clj', '.cljs', '.cljc', '.edn',             # Clojure
    '.jl',                                         # Julia
    '.elm',                                        # Elm
    '.v',                                          # V / Vlang
    '.d',                                          # D
    '.ada', '.adb', '.ads',                        # Ada
    '.f90', '.f95', '.f03',                        # Fortran (free-form)
    '.groovy',                                     # Groovy
    '.cr',                                         # Crystal
    '.purs',                                       # PureScript
    '.rkt',                                        # Racket
    '.lisp', '.cl', '.el',                         # Lisp / Common Lisp / Emacs Lisp
    '.asm', '.s',                                  # Assembly
    '.m', '.mm',                                   # Objective-C / Objective-C++
    '.vb', '.vbs',                                 # Visual Basic
    '.pp', '.pas',                                 # Pascal / Delphi
    '.tcl',                                        # Tcl
})

# Well-known files without extensions, scanned whatever their bytes are
KNOWN_FILENAMES = frozenset({
    'Makefile', 'GNUmakefile', 'makefile',
    'Dockerfile', 'Containerfile', 'Jenkinsfile',
    'go.mod', 'go.sum', 'go.work',
    'Gemfile', 'Rakefile',
    'Vagrantfile',
    'Brewfile',
    'Procfile',
    'Justfile', 'justfile',
    'SConstruct', 'SConscript',
    'Jakefile', 'Cakefile',
    'Taskfile',
    'BUILD', 'WORKSPACE',                         # Bazel
    'Podfile',                                     # CocoaPods
    'Fastfile', 'Appfile', 'Matchfile',            # Fastlane
    'Berksfile',                                   # Berkshelf
    'Guardfile',                                   # Guard
    'Dangerfile',                                  # Danger
    'Steepfile',                                   # Steep (Ruby types)
    '.gitattributes', '.gitignore', '.gitmodules',
    '.dockerignore', '.npmignore', '.eslintrc',
    '.babelrc', '.prettierrc',
    '.env',
    '.cursorrules', '.windsurfrules', '.clinerules',  # instructions for coding agents
})

# Names that carry their variant after a dot: Dockerfile.dev, .env.example.
# Path.suffix is '.dev' and '.example' for those, so no extension list can
# name them.
KNOWN_FILENAME_PREFIXES = ('Dockerfile.', 'Containerfile.', '.env.')

# Version control data and tool caches. Nothing in them is source, so
# skipping one is not worth a mention.
_NEVER_SCANNED_DIRS = frozenset({'.git', '__pycache__', '.mypy_cache', '.ruff_cache'})

# Where dependencies are installed and where frameworks and test tools write
# what they generate. --scan-deps scans these, and a scan that skipped one
# says so. dist/ and build/ are not here: they hold what a project ships,
# and some projects commit them, so they are scanned like any directory.
DEPENDENCY_DIRS = frozenset({
    'node_modules', 'vendor', 'site-packages', '.venv', 'venv', '.tox', '.eggs',
    'target', '.next', '.nuxt', 'coverage',
})

DEFAULT_SKIP_DIRS = DEPENDENCY_DIRS | _NEVER_SCANNED_DIRS

# The directories among those that hold installed packages. Below one of
# them a walk keeps to code, and a finding names the package it is in.
_DEPENDENCY_MARKERS = frozenset({'node_modules', 'vendor', 'site-packages', 'target'})

# Inside a dependency directory the walk keeps to code: files that could
# execute or be imported, compiled languages included, since their packages
# ship source. all_text lifts the restriction.
DEP_SCAN_EXTENSIONS = frozenset({
    '.js', '.cjs', '.mjs', '.ts', '.mts', '.cts',  # JavaScript/TypeScript
    '.jsx', '.tsx', '.vue', '.svelte',
    '.py', '.pyi', '.pth',                           # Python (.pth runs at startup)
    '.pyx', '.pxd', '.pxi',                          # Cython
    '.sh', '.bash', '.ps1', '.bat',                  # Shell
    '.rb',                                            # Ruby
    '.php',                                           # PHP
    '.go',                                            # Go
    '.pl',                                            # Perl
    '.rs',                                            # Rust
    '.java', '.kt', '.scala', '.groovy',             # JVM
    '.cs',                                            # C# / .NET
    '.swift',                                         # Swift
    '.c', '.cc', '.cpp', '.h', '.hh', '.hpp',        # C/C++
    '.lua',                                           # Lua
    '.dart',                                          # Dart
    '.ex', '.exs',                                    # Elixir
    '.erl', '.hrl',                                   # Erlang
    '.zig',                                           # Zig
    '.nim',                                           # Nim
    '.ml', '.mli',                                    # OCaml
    '.hs',                                            # Haskell
    '.clj', '.cljs', '.cljc',                        # Clojure
    '.jl',                                            # Julia
    '.cr',                                            # Crystal
    '.m', '.mm',                                      # Objective-C
})
# fmt: on

# Files in a dependency that are scanned for what they are called: the
# manifest names the scripts npm runs on install.
DEP_SCAN_FILENAMES = frozenset({"package.json"})

IGNORE_COMMENT = "heckler-ignore"

# Directives are found by pattern; heckler does not parse what it scans.
# Three rules keep text that only looks like a directive from working as
# one:
#
# - The comment opener starts the line or follows a space or tab, and "--"
#   is followed by one. That rules out the "#heckler-ignore" fragment of a
#   URL, a "--heckler-ignore" command-line flag and "a;heckler-ignore".
# - Only spaces and tabs may separate the parts. "\s" would also accept the
#   no-break and other exotic spaces heckler exists to report.
# - The directive ends the line.
#
# A run of the opening character is accepted, so ";;", "##", "///" and "/**"
# comments work.
_COMMENT_OPEN = r"(?<![^ \t])(?://+[ \t]*|#+[ \t]*|/\*+[ \t]*|;+[ \t]*|--[ \t]+)"
_DIRECTIVE_TAIL = r"(?:[ \t]+((?:U\+[0-9A-Fa-f]{4,6}[ \t]*)+))?[ \t]*(?:\*/[ \t]*)?$"

# Next-line suppression directive with optional codepoint list.
# Must appear on its own line (only whitespace + comment token before it).
# Format:  // heckler-ignore-next-line [U+XXXX U+YYYY ...]
#          # heckler-ignore-next-line U+FE0F
# The codepoints listed are suppressed on the next line whatever their
# severity. Without a list, the directive covers MEDIUM and below only.
_IGNORE_NEXT_LINE_RE = re.compile(
    r"^[ \t]*" + _COMMENT_OPEN + "heckler-ignore-next-line" + _DIRECTIVE_TAIL
)

# Legacy inline directive (end-of-line anchor prevents mid-string injection).
# Deprecated in favor of heckler-ignore-next-line but still supported for
# project code. Never honored in dependency code.
_IGNORE_INLINE_RE = re.compile(_COMMENT_OPEN + "heckler-ignore" + _DIRECTIVE_TAIL)

_CODEPOINT_RE = re.compile(r"U\+([0-9A-Fa-f]{4,6})")

# What a directive without a codepoint list may suppress. The characters
# behind Trojan Source, Glassworm and tag smuggling are all rated above this,
# so hiding one of them takes a directive that names it.
_BARE_DIRECTIVE_MAX = Severity.MEDIUM


def _parse_suppressed_codepoints(directive_match: re.Match[str]) -> frozenset[int] | None:
    """Extract codepoints from a suppression directive.

    Returns a frozenset of codepoint ints, or None for a directive without a
    list, which covers every finding up to ``_BARE_DIRECTIVE_MAX``.
    """
    cp_str = directive_match.group(1)
    if not cp_str:
        return None  # no codepoints listed
    return frozenset(int(m.group(1), 16) for m in _CODEPOINT_RE.finditer(cp_str))


# str.splitlines() is not used: it also breaks on U+2028, U+2029 and a few
# control characters, consuming them before the regex can report them. CR on
# its own is a line break here, as it is in every editor; otherwise a file
# with CR-only line endings is one long line and a directive at its end
# would cover all of it.
_LINE_BREAK_RE = re.compile(r"\r\n|\r|\n")

# More presentation selectors than this on one line are reported once, at
# LOW. Each sits inside a well-formed emoji and is INFO by itself, but the
# choice between U+FE0E, U+FE0F and neither can carry data across a row of
# them.
_MAX_EMOJI_SELECTORS_PER_LINE = 10

# Wrapping a row gets it under the limit for a line, so two counts are kept
# for the whole file. An emoji can be written bare, with U+FE0E or with
# U+FE0F; whichever a file mostly uses for an emoji is its presentation
# there, and more occurrences than this in another one are reported once, at
# LOW. A joiner between two emoji is there or it is not, which is a choice
# too, so more joiners than the second limit are reported the same way.
_MAX_VARIED_EMOJI_PER_FILE = 10
_MAX_EMOJI_JOINERS_PER_FILE = 50


_BINARY_CHECK_SIZE = 8192

# Nobody reads this many findings for one file. Stopping here keeps a binary
# that carries a source extension, where control bytes are everywhere, from
# turning into millions of findings.
_MAX_FINDINGS_PER_FILE = 10_000

# Maximum file size to scan (50 MB). A larger file is not read, to prevent
# memory exhaustion from adversarially large inputs. It is recorded in
# Scanner.skipped, because a file nobody looked at is not a clean one, or in
# Scanner.binary when its start looks binary.
_MAX_SCAN_FILE_SIZE = 50 * 1024 * 1024

# BOM signatures ordered longest-first so UTF-32 is checked before UTF-16.
_BOM_TABLE: list[tuple[bytes, str]] = [
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
]

_ENCODING_LABELS = {
    "utf-8": "UTF-8",
    "utf-16-le": "UTF-16 LE",
    "utf-16-be": "UTF-16 BE",
    "utf-32-le": "UTF-32 LE",
    "utf-32-be": "UTF-32 BE",
}

# A declaration of the source encoding, as Python's tokenizer finds it
# (PEP 263): a comment on line 1 or 2. Matched on bytes, so what surrounds it
# need not be valid in any encoding.
_DECLARATION_RE = re.compile(rb"^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)")
_LINE_BREAK_BYTES_RE = re.compile(rb"\r\n|\r|\n")

# What a declaration is written in. A codec that does not read these bytes
# as themselves cannot have been the one it was read in, and Python refuses
# such a file as source.
_DECLARATION_BYTES = b"# -*- coding= : x-y_z.0 -*-\t\f\r\n"


def _first_lines(raw: bytes, count: int = 2) -> list[bytes]:
    lines: list[bytes] = []
    start = 0
    for brk in _LINE_BREAK_BYTES_RE.finditer(raw):
        lines.append(raw[start : brk.start()])
        start = brk.end()
        if len(lines) == count:
            return lines
    return [*lines, raw[start:]][:count]


def _normal_name(name: str) -> str:
    """*name* as Python's tokenizer normalises it before it looks the codec up."""
    enc = name[:12].lower().replace("_", "-")
    if enc == "utf-8" or enc.startswith("utf-8-"):
        return "utf-8"
    latin = ("latin-1", "iso-8859-1", "iso-latin-1")
    if enc in latin or enc.startswith(tuple(f"{n}-" for n in latin)):
        return "iso-8859-1"
    return name


@functools.lru_cache(maxsize=64)
def _source_codec(name: str) -> str | None:
    """The codec a file that declares *name* is read in as well, or None for no other reading.

    Raises LookupError for a name this Python does not know.
    """
    codec = codecs.lookup(_normal_name(name)).name
    if codec in ("utf-8", "utf-8-sig"):
        return None
    try:
        same = _DECLARATION_BYTES.decode(codec, errors="replace") == _DECLARATION_BYTES.decode(
            "ascii"
        )
    except (LookupError, UnicodeError):  # not a text encoding, or no lenient decoding
        return None
    return codec if same else None


def _declared_codecs(raw: bytes) -> tuple[list[str], list[str]]:
    """The codecs the first two lines of *raw* declare, and the names this Python does not know."""
    known: list[str] = []
    unknown: list[str] = []
    for line in _first_lines(raw.removeprefix(codecs.BOM_UTF8)):
        match = _DECLARATION_RE.match(line)
        if not match:
            continue
        name = match.group(1).decode("ascii")
        try:
            codec = _source_codec(name)
        except LookupError:
            unknown.append(name)
            continue
        if codec and codec not in known:
            known.append(codec)
    return known, unknown


def _same_lines(first: str, other: str) -> frozenset[int]:
    """The numbers of the lines that read the same in two readings of a file."""
    pairs = zip(_LINE_BREAK_RE.split(first), _LINE_BREAK_RE.split(other), strict=False)
    return frozenset(n for n, (a, b) in enumerate(pairs, 1) if a == b)


def _is_valid_utf8(raw: bytes) -> bool:
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


_NOTHING: frozenset[int] = frozenset()

# What a lenient decoder puts in place of each byte it cannot read.
_REPLACEMENT = chr(0xFFFD)

# The C0 controls that text has no use for: all but tab, LF, FF and CR.
# Escape is left out as well. A log with colours in it is full of them, and
# it is text, with escape sequences that are worth reporting.
_CONTROL_BYTES = bytes(b for b in range(0x20) if b not in b"\t\n\x0c\r\x1b")

# Data in which more than one byte in this many is one that text does not
# hold is not text. Compressed data is at one in ten and an executable is
# higher still; a text file with a stray NUL in it is far below.
_TEXT_RATIO = 32

# Fewer control bytes than this never make a file look binary, whatever
# share of it they are. One byte is more than one in 32 of a file shorter
# than that, and no single byte decides how a file is read.
_MIN_CONTROL_BYTES = 2

# The start of a file is not all of it, and padding there costs little: 260
# control bytes in the first comment of a script made it look binary. So a
# file that looks binary is read in full before it is left out, and is left
# out only when more than one byte in this many, over the whole of it, is a
# control byte or invalid UTF-8. A file with less than that is mostly text,
# and is scanned for the text inside it.
#
# This is where the reading stops. A file that is more than a quarter junk
# is binary, whatever text it also holds: it is left out. Hiding text that
# way takes junk on the scale of the file, and what an image, an archive or
# an executable holds is not looked at.
#
# Either way the file is named in the report, in Scanner.binary. The reading
# of a file that is mostly text is not a whole one (see _MIN_TEXT_RUN), so
# it adds findings to the name and does not take the place of it.
_MOSTLY_TEXT_RATIO = 4

# In a file that looks binary and is mostly text, what is scanned is each
# run of at least this many characters that decode as UTF-8, or the whole
# file when all of it does.
#
# What ends a run is a byte that is not UTF-8, and nothing else. A control
# byte does not, NUL included: one on each side of a flagged character would
# cut it out of the text, and they show in a diff as little as the character
# does.
#
# The length keeps chance out. Bytes that are not text spell a flagged code
# point now and then: about 70 times per MB in random bytes, nearly always
# with an invalid byte a few characters away. Measured over 1 GB of them, a
# run of 16 would still report two in 50 MB, and a run of 32 none at all.
#
# It is also a way out of the reading, and a cheap one: an invalid byte
# every 31 characters keeps all of a file out of every run, at a few bytes
# in a hundred. Control characters are not reported from a run either, since
# padding and the binary parts of a file are made of them. Neither is closed
# by reporting more, which would report chance. A file read this way is
# named in the report whatever the reading found, so what it left out is
# never left out without a word.
_MIN_TEXT_RUN = 32
_TEXT_RUN_RE = re.compile(f"[^{_REPLACEMENT}]{{{_MIN_TEXT_RUN},}}")

# How a finding from that reading is marked.
_LOOKS_BINARY = "in a file that looks binary"


def _control_bytes(data: bytes) -> int:
    """How many bytes of *data* are control characters that text does not hold."""
    return len(data) - len(data.translate(None, _CONTROL_BYTES))


def _is_utf8_text(data: bytes, ratio: int = _TEXT_RATIO) -> bool:
    """False if too much of *data* is control bytes or invalid UTF-8 to be text.

    Too much is more than one byte in *ratio*. It takes a share of the
    bytes to say so. A single NUL proves nothing: putting one in a comment
    costs one byte.
    """
    controls = _control_bytes(data)
    if controls * ratio > len(data):
        return False  # settled, without decoding what may be 50 MB
    invalid = data.decode("utf-8", errors="replace").count(_REPLACEMENT)
    return (controls + invalid) * ratio <= len(data)


def _detect_bom_encoding(raw: bytes) -> str | None:
    """Return the codec name if *raw* starts with a UTF-16/32 BOM."""
    for sig, codec in _BOM_TABLE:
        if raw[: len(sig)] == sig:
            return codec
    return None


def _bom_matches_content(raw: bytes, codec: str) -> bool:
    """False if *raw* starts with the BOM for *codec* but is not in it.

    A BOM is two or four bytes that anyone can put in front of a UTF-8 file.
    Decoded as UTF-16, such a file is a run of unrelated CJK characters with
    nothing to report in it, while every tool that ignores or rejects the
    BOM still reads the text that is really there.
    """
    if codec.startswith("utf-16"):
        # Read as UTF-8, real UTF-16 is anything but text: half the bytes of
        # Latin text are NUL, the high byte of a Cyrillic or Thai letter is
        # another control, and CJK is mostly invalid. The whole file is
        # measured, so that neither one NUL nor a block of padding at the
        # top settles it.
        body = raw[2:]
        return not body or not _is_utf8_text(body)
    # UTF-32: every four bytes have to be a code point.
    body = raw[4:]
    try:
        body[: len(body) - len(body) % 4].decode(codec)
    except UnicodeDecodeError:
        return False
    return True


# The upper byte of a UTF-16 unit for the scripts below U+2000 (Latin, Greek,
# Cyrillic, Hebrew, Arabic, Thai and more), without the three values that
# are tab, LF and CR in a UTF-8 file.
_UTF16_HIGH_BYTES = bytes(b for b in range(0x20) if b not in b"\t\n\r")


def _guess_bomless_utf16(head: bytes, high_bytes: bytes = b"\x00") -> str | None:
    """Return a UTF-16 codec if *head* looks like UTF-16 text without a BOM.

    ASCII in UTF-16 has a NUL in every other byte: the second of each pair
    in little-endian order, the first in big-endian. A quarter of the pairs
    is enough to call it, provided the other byte of a pair is almost never
    NUL. A stray NUL or two in a UTF-8 file is far below that.

    *high_bytes* is what counts as the upper byte of a pair. NUL alone
    finds Latin text; ``_UTF16_HIGH_BYTES`` finds the other scripts whose
    upper byte is a control character.
    """
    pairs = len(head) // 2
    if pairs < 2:
        return None
    first, second = head[0 : pairs * 2 : 2], head[1 : pairs * 2 : 2]
    high_first = len(first) - len(first.translate(None, high_bytes))
    high_second = len(second) - len(second.translate(None, high_bytes))
    if high_second * 4 >= pairs and first.count(0) * 8 <= high_second:
        return "utf-16-le"
    if high_first * 4 >= pairs and second.count(0) * 8 <= high_first:
        return "utf-16-be"
    return None


def _guess_bomless_utf32(head: bytes) -> str | None:
    """Return a UTF-32 codec if *head* looks like UTF-32 text without a BOM.

    A code point takes four bytes and the upper two are NUL for everything
    in the Basic Multilingual Plane, while the lowest is almost never NUL.
    """
    units = len(head) // 4
    if units < 2:
        return None
    nul = [head[offset : units * 4 : 4].count(0) for offset in range(4)]
    if nul[2] * 4 >= units * 3 and nul[3] * 4 >= units * 3 and nul[0] * 8 <= units:
        return "utf-32-le"
    if nul[0] * 4 >= units * 3 and nul[1] * 4 >= units * 3 and nul[3] * 8 <= units:
        return "utf-32-be"
    return None


def _other_readings(raw: bytes, bom_codec: str | None, believed: bool) -> list[tuple[str, bool]]:
    """What to scan a file as besides the encoding it presents itself in.

    Each reading is a codec and whether control characters are reported
    from it. *believed* says whether the content matches *bom_codec*.
    """
    if bom_codec is None:
        head = raw[:_BINARY_CHECK_SIZE]
        guess = _guess_bomless_utf32(head) or _guess_bomless_utf16(head, _UTF16_HIGH_BYTES)
        return [(guess, True)] if guess else []
    if believed:
        return [("utf-8", False)]
    if bom_codec == "utf-32-le":
        # FF FE 00 00 is also the UTF-16 BOM followed by a NUL character.
        return [("utf-8", True), ("utf-16-le", True)]
    return [("utf-8", True)]


def _text_inside(decoded: str) -> str | None:
    """What there is to scan in a file that looks binary, or None for nothing.

    *decoded* is the file read as UTF-8, with U+FFFD for each byte that is
    not. The result is its text runs, each where it is in the file: what
    lies between two of them is cut down to its line breaks and to its
    length on the lines it shares with a run. A scan of the result reports
    what is in the runs and nothing else, at the line and column a finding
    has in the file. A run with nothing in it to report is treated like
    what is not text, and nothing is kept of what follows the last run.
    """
    if _REPLACEMENT not in decoded:
        return decoded  # all of it is UTF-8, so all of it is one run
    pieces: list[str] = []
    done = 0  # how much of *decoded* is in pieces
    for run in _TEXT_RUN_RE.finditer(decoded):
        if DANGEROUS_NON_CONTROL_RE.search(decoded, run.start(), run.end()):
            pieces.append(_outline(decoded, done, run.start()))
            pieces.append(run.group())
            done = run.end()
    return "".join(pieces) if pieces else None


def _outline(decoded: str, start: int, end: int) -> str:
    """A stand-in for ``decoded[start:end]`` with nothing in it to report.

    It has as many line breaks, as many characters before the first of them
    and as many after the last, so what comes after it stays on the line
    and in the column where it was.
    """
    if not _LINE_BREAK_RE.search(decoded, start, end):
        return _REPLACEMENT * (end - start)
    line_feed, carriage_return = decoded.find("\n", start, end), decoded.find("\r", start, end)
    first = min(at for at in (line_feed, carriage_return) if at != -1)
    last = max(decoded.rfind("\n", start, end), decoded.rfind("\r", start, end))
    # CR LF is one line break, as it is for _LINE_BREAK_RE.
    breaks = (
        decoded.count("\n", start, end)
        + decoded.count("\r", start, end)
        - decoded.count("\r\n", start, end)
    )
    return _REPLACEMENT * (first - start) + "\n" * breaks + _REPLACEMENT * (end - last - 1)


def _varied_presentations(text: str, styled: dict[tuple[str, int], int]) -> int:
    """How many emoji in *text* are not in the presentation that emoji mostly has there.

    *styled* says how often each emoji is followed by each presentation
    selector. The third way to write it, bare, is counted here.
    """
    selectors = "".join(chr(cp) for cp in sorted(PRESENTATION_SELECTORS))
    varied = 0
    for base in {base for base, _ in styled}:
        forms = [count for (styled_base, _), count in styled.items() if styled_base == base]
        forms.append(len(re.findall(re.escape(base) + f"(?![{selectors}])", text)))
        varied += sum(forms) - max(forms)
    return varied


def _label_reading(findings: list[Finding], reading: str) -> None:
    """Mark findings with the reading of the file they come from, where it is not the plain one."""
    for finding in findings:
        finding.char_name = f"{finding.char_name} ({reading})"


def _read_as(codec: str) -> str:
    """The label for findings from one of several decodings of a file."""
    return f"read as {_ENCODING_LABELS[codec]}"


def _is_script(filepath: Path) -> bool:
    """True if the file starts with ``#!``, which makes it a script whatever it is called."""
    try:
        with open(filepath, "rb") as f:
            return f.read(2) == b"#!"
    except OSError:
        return False


def _is_regular_file(filepath: Path) -> bool:
    """False for a named pipe, a socket or a device, which a walk does not open.

    Opening a pipe waits until something writes to it, and nothing may.
    """
    try:
        return stat.S_ISREG(os.lstat(filepath).st_mode)
    except OSError:
        # Not known to be anything else. Reading it will fail too, and that
        # is recorded.
        return True


def _is_known_name(name: str) -> bool:
    """True for a file name that is scanned whatever its extension."""
    return name in KNOWN_FILENAMES or name.startswith(KNOWN_FILENAME_PREFIXES)


@dataclass
class Scanner:
    skip_dirs: frozenset[str] = field(default_factory=lambda: DEFAULT_SKIP_DIRS)
    #: Extensions that mark a file as source, so that it is scanned whatever
    #: its bytes are. A directory walk scans every other file too when its
    #: content is text. ``None`` is the older way to ask for ``all_text``.
    text_extensions: frozenset[str] | None = field(default_factory=lambda: DEFAULT_TEXT_EXTENSIONS)
    #: Scan every text file inside dependency directories as well, where a
    #: walk otherwise keeps to code.
    all_text: bool = False
    #: Leave out a file passed by name when its content is not text, as a
    #: directory walk does. Without this such a file is always scanned.
    skip_binary: bool = False
    severity_threshold: Severity = Severity.LOW
    exclude_patterns: list[str] = field(default_factory=list[str])
    allow_bom: bool = True
    scan_deps: bool = False
    diff_only: bool = False
    allow_emoji: bool = True
    # False ignores heckler-ignore directives, to list what they are hiding.
    honor_directives: bool = True

    # What the scans so far left out or held back, for the caller to report.
    #: ``(path, reason)`` for each file or directory that could not be scanned.
    skipped: list[tuple[str, str]] = field(
        default_factory=list[tuple[str, str]], init=False, repr=False, compare=False
    )
    #: Number of findings a directive suppressed, by file.
    suppressed: dict[str, int] = field(
        default_factory=dict[str, int], init=False, repr=False, compare=False
    )
    #: Findings reported from a line whose directive lists no codepoints.
    unlisted: int = field(default=0, init=False, repr=False, compare=False)
    #: Directories that were not entered because of their name, other than
    #: version control data and tool caches.
    skipped_dirs: list[str] = field(
        default_factory=list[str], init=False, repr=False, compare=False
    )
    #: Files that were not scanned as text, because their start looks
    #: binary. One of them is left out when more than a quarter of it is
    #: control bytes or invalid UTF-8, or when it is too large to read. The
    #: rest are mostly text and were scanned for the text inside them, which
    #: is not all a scan of text reports, so they are listed as well. A file
    #: whose name marks it as source is never one of them.
    binary: list[str] = field(default_factory=list[str], init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.text_extensions is None:
            self.all_text = True

    def scan_text(self, text: str, filename: str = "<string>") -> list[Finding]:
        """Scan a text string for dangerous Unicode. The core primitive."""
        return self._scan_text(text, filename)

    def _scan_text(
        self,
        text: str,
        filename: str,
        *,
        controls: bool = True,
        directives: bool = True,
        record: set[tuple[int, int]] | None = None,
        already: AbstractSet[tuple[int, int]] = frozenset(),
        trusted: frozenset[int] | None = None,
    ) -> list[Finding]:
        """scan_text() for one reading of a file.

        Without *controls*, control characters are not reported, which
        leaves U+00A0 and up. Without *directives*, no suppression directive
        is honoured, whatever the scanner is set to.

        *record* gains the ``(line, code point)`` of what is reported or
        suppressed, and *already* holds such pairs from an earlier reading:
        they are skipped before a suppression is counted. *trusted* is the
        set of lines where a directive counts, or None for all of them.
        """
        findings: list[Finding] = []
        source, package = self._classify_path(filename)
        # Never honor suppression directives in dependency code —
        # a malicious package author could embed them to hide attacks.
        honor = self.honor_directives and source != "dependency" and not self.scan_deps
        honor = honor and directives
        flagged = DANGEROUS_UNICODE_RE if controls else DANGEROUS_NON_CONTROL_RE
        nul_seen = False

        # What a directive covers on the current line: the codepoints it
        # lists and, if it lists none, everything up to _BARE_DIRECTIVE_MAX.
        bare, listed = False, _NOTHING
        next_bare, next_listed = False, _NOTHING
        line_num, line = 0, ""

        # Counts over the whole file, and where the first of each kind is.
        styled: dict[tuple[str, int], int] = {}
        first_styled: tuple[int, int, str] | None = None
        joiners = 0
        first_joiner: tuple[int, int, str] | None = None

        def report(col: int, cp: int, info: CharInfo) -> None:
            if not info.severity >= self.severity_threshold:
                return
            if (line_num, cp) in already:
                return  # the first reading reported it on this line
            if record is not None:
                record.add((line_num, cp))
            if cp in listed or (bare and info.severity <= _BARE_DIRECTIVE_MAX):
                self.suppressed[filename] = self.suppressed.get(filename, 0) + 1
                return
            if bare:
                self.unlisted += 1
            findings.append(
                Finding.from_match(
                    filepath=filename,
                    line_num=line_num,
                    col=col + 1,
                    cp=cp,
                    info=info,
                    line_content=line,
                    source=source,
                    package=package,
                )
            )

        for line_num, line in enumerate(_LINE_BREAK_RE.split(text), 1):
            bare, listed = next_bare, next_listed
            next_bare, next_listed = False, _NOTHING
            if honor and (trusted is None or line_num in trusted):
                directive = _IGNORE_NEXT_LINE_RE.match(line)
                if directive:
                    # Covers the next line. This one is scanned like any other.
                    codepoints = _parse_suppressed_codepoints(directive)
                    next_bare, next_listed = codepoints is None, codepoints or _NOTHING
                else:
                    # Legacy inline directive (end-of-line anchored)
                    directive = _IGNORE_INLINE_RE.search(line)
                    if directive:
                        codepoints = _parse_suppressed_codepoints(directive)
                        bare = bare or codepoints is None
                        listed = listed | (codepoints or _NOTHING)

            emoji_selectors = 0
            first_emoji_selector = -1
            for match in flagged.finditer(line):
                cp = ord(match.group()[0])
                # BOM at file start is typically legitimate
                if cp == 0xFEFF and line_num == 1 and match.start() == 0 and self.allow_bom:
                    continue
                if cp == 0:
                    # One finding says it: this file holds NUL bytes.
                    if nul_seen:
                        continue
                    nul_seen = True
                info = get_char_info(cp)
                if self.allow_emoji and is_emoji_context(line, match.start()):
                    # Part of a well-formed emoji. Still reported, but at
                    # INFO, which is below every default threshold.
                    info = CharInfo(f"{info.name} (in emoji)", info.category, Severity.INFO)
                    if cp in PRESENTATION_SELECTORS:
                        if not emoji_selectors:
                            first_emoji_selector = match.start()
                        emoji_selectors += 1
                        base = line[match.start() - 1]
                        if base not in KEYCAP_BASES:  # or every digit would count as bare
                            styled[(base, cp)] = styled.get((base, cp), 0) + 1
                            first_styled = first_styled or (line_num, match.start(), line)
                    elif cp == ZERO_WIDTH_JOINER:
                        joiners += 1
                        first_joiner = first_joiner or (line_num, match.start(), line)
                report(match.start(), cp, info)
                if len(findings) >= _MAX_FINDINGS_PER_FILE:
                    return self._stopped_early(findings, filename)

            if emoji_selectors > _MAX_EMOJI_SELECTORS_PER_LINE:
                report(
                    first_emoji_selector,
                    ord(line[first_emoji_selector]),
                    CharInfo(
                        f"{emoji_selectors} emoji presentation selectors on one line",
                        ThreatCategory.VARIATION_SELECTOR,
                        Severity.LOW,
                    ),
                )
                if len(findings) >= _MAX_FINDINGS_PER_FILE:
                    return self._stopped_early(findings, filename)

        # A count over the file belongs to no line, so no line's directive
        # covers it. It is reported where the first of its kind is.
        bare, listed = False, _NOTHING
        if first_styled and sum(styled.values()) > _MAX_VARIED_EMOJI_PER_FILE:
            varied = _varied_presentations(text, styled)
            if varied > _MAX_VARIED_EMOJI_PER_FILE:
                line_num, column, line = first_styled
                report(
                    column,
                    ord(line[column]),
                    CharInfo(
                        f"{varied} emoji written with more than one presentation in this file",
                        ThreatCategory.VARIATION_SELECTOR,
                        Severity.LOW,
                    ),
                )
        if first_joiner and joiners > _MAX_EMOJI_JOINERS_PER_FILE:
            line_num, column, line = first_joiner
            report(
                column,
                ZERO_WIDTH_JOINER,
                CharInfo(
                    f"{joiners} zero width joiners between emoji in this file",
                    ThreatCategory.ZERO_WIDTH,
                    Severity.LOW,
                ),
            )
        return findings

    @staticmethod
    def _stopped_early(findings: list[Finding], filename: str) -> list[Finding]:
        write_err(
            f"Warning: {filename}: stopped after {_MAX_FINDINGS_PER_FILE}"
            " findings; the rest of the file was not scanned.",
        )
        return findings

    def scan_file(self, filepath: Path) -> list[Finding]:
        """Read a file and scan its contents.

        A file that cannot be read, or is too large to, yields no findings
        and is recorded in ``skipped``.
        """
        name = str(filepath)
        raw = self._read(filepath)
        if raw is None:
            return []

        # Detect non-UTF-8 encodings via BOM signatures.  UTF-16/32 files
        # contain embedded null bytes that would otherwise cause the scanner
        # to treat them as binary and skip the content entirely — an attacker
        # could exploit this by committing a UTF-16 encoded file.
        #
        # Without a BOM the file is read as UTF-8. A NUL byte does not end
        # the scan: JavaScript accepts one inside a comment, PHP before its
        # opening tag, and bash after the first line, so stopping there
        # would let a single byte hide everything that follows it. Whether a
        # file is worth scanning at all is decided by the caller.
        bom_codec = _detect_bom_encoding(raw)
        text = raw.decode(bom_codec or "utf-8", errors="replace")
        first: set[tuple[int, int]] = set()
        findings = self._scan_text(text, name, record=first)

        # The encoding a file announces is not always the one it is in: a
        # BOM in front of UTF-8 text, or UTF-16 text with no BOM. Scan the
        # other reading too, so that neither can hide the characters. One of
        # the readings is then noise (two ASCII bytes taken as one UTF-16
        # unit can land on a flagged code point), so each finding says which
        # reading it comes from.
        #
        # A BOM that the content matches is believed, but nothing is staked
        # on it: what makes it believable is a share of the bytes, and
        # padding can supply that. Such a file is read as UTF-8 as well. Of
        # that reading only U+00A0 and up is reported, because below it real
        # UTF-16 read as UTF-8 is nothing but controls: U+0004 for the high
        # byte of every Cyrillic letter, a C1 control for the two bytes of
        # some CJK ones.
        believed = bom_codec is not None and _bom_matches_content(raw, bom_codec)
        if bom_codec and not believed:
            _label_reading(findings, _read_as(bom_codec))
            findings[:0] = self._bom_mismatch(name, bom_codec)
        for codec, controls in _other_readings(raw, bom_codec, believed):
            decoded = raw.decode(codec, errors="replace")
            reading = self._scan_text(decoded, name, controls=controls)
            _label_reading(reading, _read_as(codec))
            findings.extend(reading)
        findings.extend(self._declared_readings(raw, name, text, first))
        return findings

    def _declared_readings(
        self,
        raw: bytes,
        name: str,
        first_text: str | None,
        first: AbstractSet[tuple[int, int]],
        *,
        looks_binary: bool = False,
    ) -> list[Finding]:
        """The file read in each encoding its first two lines declare, less the first reading."""
        declared, unknown = _declared_codecs(raw)
        if unknown and not _is_valid_utf8(raw):
            for label in unknown:
                reason = (
                    f"it declares an encoding this Python does not know ({label});"
                    " it was read as UTF-8 only"
                )
                self.skipped.append((name, reason))
        findings: list[Finding] = []
        for codec in declared:
            if first_text is None:
                first_text = raw.decode("utf-8", errors="replace")
            text = raw.decode(codec, errors="replace")
            if text == first_text:
                continue
            reading = self._scan_text(
                text,
                name,
                controls=not looks_binary,
                directives=not looks_binary,
                already=first,
                trusted=None if looks_binary else _same_lines(first_text, text),
            )
            _label_reading(reading, f"read as {codec.upper()}, as declared")
            findings.extend(reading)
        return findings

    def _scan_text_inside(self, filepath: Path) -> list[Finding]:
        """Scan a file whose start looks binary, unless all of it says the same.

        What the start of a file looks like is up to whoever wrote it:
        padding in the first comment of a script is enough. So the whole
        file is read. If more than a quarter of it is control bytes and
        invalid UTF-8 (see ``_MOSTLY_TEXT_RATIO``), it is binary, and is left
        out. Text inside a file like that is not scanned.

        Otherwise the file is mostly text, and every run of text in it is
        scanned (see ``_MIN_TEXT_RUN``): without control characters, which
        the padding is made of, and without suppression directives, since
        git shows no diff for a file it takes for binary and nobody reviews
        a directive in one.

        The file is recorded in ``binary`` in both cases. Control characters
        and what lies outside the runs can hold what a scan is for, and this
        reading reports neither, so a file it found nothing in has still not
        been scanned as text is.

        A file too large to read is left out as binary too. It is recorded
        in ``binary`` and not in ``skipped``, so the large media files of a
        repository do not fail a run.
        """
        raw = self._read(filepath, looks_binary=True)
        if raw is None:
            return []
        self.binary.append(str(filepath))
        if not _is_utf8_text(raw, _MOSTLY_TEXT_RATIO):
            return []
        # Everything that is reported from this reading is U+00A0 or above,
        # and none of that is in ASCII.
        if raw.isascii():
            return []
        text = _text_inside(raw.decode("utf-8", errors="replace"))
        if text is None:
            return []
        findings = self._scan_text(text, str(filepath), controls=False, directives=False)
        _label_reading(findings, _LOOKS_BINARY)
        return findings

    def _read(self, filepath: Path, looks_binary: bool = False) -> bytes | None:
        """The bytes of a file, or None, with the reason recorded, if it was not read."""
        name = str(filepath)
        try:
            if filepath.stat().st_size > _MAX_SCAN_FILE_SIZE:
                if looks_binary:
                    self.binary.append(name)
                else:
                    limit = _MAX_SCAN_FILE_SIZE // (1024 * 1024)
                    self.skipped.append((name, f"it is larger than {limit} MB"))
                return None
            return filepath.read_bytes()
        except OSError as e:
            self.skipped.append((name, f"it could not be read ({e.strerror or e})"))
            return None

    def _bom_mismatch(self, filename: str, codec: str) -> list[Finding]:
        """The finding for a byte order mark that the content does not match."""
        family = _ENCODING_LABELS[codec].split()[0]
        info = CharInfo(
            f"Byte order mark for {family} on a file that is not {family}",
            ThreatCategory.ZERO_WIDTH,
            Severity.HIGH,
        )
        if not info.severity >= self.severity_threshold:
            return []
        source, package = self._classify_path(filename)
        return [Finding.from_match(filename, 1, 1, 0xFEFF, info, "", source, package)]

    def scan_path(self, root: Path, *, by_content: bool = False) -> list[Finding]:
        """Recursively scan a directory or single file.

        A file passed by name is scanned whatever it holds. With
        *by_content*, or with ``skip_binary`` set, it is treated as a
        directory walk treats it, and left out when its content is binary.
        """
        extensions = self._source_extensions()
        if root.is_file():
            # A file named on the command line (which is how pre-commit passes
            # them) still honours the allowlist, so .heckler.yml means the
            # same thing whether heckler walks a directory or is handed files.
            if self._is_excluded(root):
                return []
            if self.skip_binary or by_content:
                return self._scan_by_content(root, extensions)
            return self.scan_file(root)
        if not root.is_dir():
            reason = "it is not a file or a directory" if root.exists() else "it does not exist"
            self.skipped.append((str(root), reason))
            return []

        all_findings: list[Finding] = []
        effective_skip = self._effective_skip_dirs()

        def unreadable(error: OSError) -> None:
            reason = f"the directory could not be read ({error.strerror or error})"
            self.skipped.append((str(error.filename or root), reason))

        for dirpath, dirnames, filenames in os.walk(root, onerror=unreadable, followlinks=False):
            # Filter directories in-place — skip symlinks and excluded dirs.
            # Sorted, here and below, so the report comes out in the same
            # order on every filesystem.
            entered: list[str] = []
            for d in sorted(dirnames):
                path = os.path.join(dirpath, d)
                if d in effective_skip:
                    if d not in _NEVER_SCANNED_DIRS:
                        self.skipped_dirs.append(path)
                elif not os.path.islink(path):
                    entered.append(d)
            dirnames[:] = entered
            dp = Path(dirpath)
            code_only = not self.all_text and self._in_dependency(dp)
            for fname in sorted(filenames):
                fpath = dp / fname
                if os.path.islink(fpath) or self._is_excluded(fpath):
                    continue
                if not _is_regular_file(fpath):
                    # Named and left shut, before anything below opens it.
                    self.skipped.append((str(fpath), "it is not a regular file"))
                elif not code_only:
                    all_findings.extend(self._scan_by_content(fpath, extensions))
                elif self.is_dependency_source(fpath):
                    all_findings.extend(self.scan_file(fpath))
        return all_findings

    def _scan_by_content(self, filepath: Path, extensions: frozenset[str]) -> list[Finding]:
        """Scan a file as a directory walk does, or leave it out as binary.

        As text when its name marks it as source or its start is text. A
        file whose start looks binary is read in full, and is scanned for
        the text inside it unless the whole of it is binary.
        """
        if self.is_text_file(filepath, extensions):
            return self.scan_file(filepath)
        return self._scan_text_inside(filepath)

    def scan_paths(self, paths: list[Path]) -> list[Finding]:
        """Scan multiple paths (files or directories)."""
        all_findings: list[Finding] = []
        for p in paths:
            all_findings.extend(self.scan_path(p))
        return all_findings

    def _effective_skip_dirs(self) -> frozenset[str]:
        if self.scan_deps:
            # build/ and dist/ are named for the configuration that skips
            # them in the project: a package keeps its code in them.
            return self.skip_dirs - DEPENDENCY_DIRS - {"build", "dist"}
        return self.skip_dirs

    def _source_extensions(self) -> frozenset[str]:
        """The extensions that are scanned whatever the file holds."""
        if self.text_extensions is None:
            return DEFAULT_TEXT_EXTENSIONS
        return self.text_extensions

    @staticmethod
    def _in_dependency(dirpath: Path) -> bool:
        """True inside a directory that holds installed packages."""
        return not _DEPENDENCY_MARKERS.isdisjoint(dirpath.parts)

    def _classify_path(self, filepath: str) -> tuple[str, str | None]:
        """Determine if a file is project code or a dependency, and extract package name."""
        parts = filepath.replace("\\", "/").split("/")
        if "node_modules" in parts:
            # The last one: pnpm keeps each package in
            # node_modules/.pnpm/<name>@<version>/node_modules/<name>, and a
            # nested node_modules holds a package of its own.
            idx = len(parts) - 1 - parts[::-1].index("node_modules")
            if idx + 1 < len(parts):
                pkg = parts[idx + 1]
                # Handle scoped packages: @scope/name
                if pkg.startswith("@") and idx + 2 < len(parts):
                    pkg = f"{pkg}/{parts[idx + 2]}"
                return "dependency", pkg
        if "site-packages" in parts:
            idx = parts.index("site-packages")
            if idx + 1 < len(parts):
                return "dependency", parts[idx + 1]
        if "vendor" in parts:
            idx = parts.index("vendor")
            if idx + 1 < len(parts):
                return "dependency", parts[idx + 1]
        if "target" in parts:
            idx = parts.index("target")
            if idx + 1 < len(parts):
                return "dependency", parts[idx + 1]
        return "project", None

    def _is_excluded(self, filepath: Path) -> bool:
        """Check if a file matches any exclude pattern."""
        fp_str = str(filepath)
        return any(_glob_match(fp_str, pattern) for pattern in self.exclude_patterns)

    @staticmethod
    def is_text_file(filepath: Path, extensions: frozenset[str] = DEFAULT_TEXT_EXTENSIONS) -> bool:
        """Whether a directory walk scans a file as text.

        It does unless the start of the file looks binary, as images,
        archives and the like do. A name that marks the file as source (one
        of *extensions*, or a well-known file name) is scanned as text
        whatever it holds, so nothing written into such a file can opt it
        out. A file this is false for is not left out yet: the walk reads
        it in full, and scans the text inside it when it is mostly text.
        """
        return Scanner._is_source_name(filepath, extensions) or not Scanner._is_binary(filepath)

    @staticmethod
    def is_dependency_source(filepath: Path) -> bool:
        """Whether a file inside a dependency is scanned, unless the scan is of all text.

        Code, by extension or by name, and anything that starts with ``#!``:
        the scripts a package installs on ``PATH`` seldom have an extension.
        """
        return (
            filepath.suffix.lower() in DEP_SCAN_EXTENSIONS
            or filepath.name in DEP_SCAN_FILENAMES
            or _is_known_name(filepath.name)
            or _is_script(filepath)
        )

    @staticmethod
    def _is_source_name(
        filepath: Path, extensions: frozenset[str] = DEFAULT_TEXT_EXTENSIONS
    ) -> bool:
        """True if the name alone marks the file as source."""
        return filepath.suffix.lower() in extensions or _is_known_name(filepath.name)

    @staticmethod
    def _is_binary(filepath: Path) -> bool:
        """Whether the start of a file is too full of control bytes to be text.

        One NUL does not make a file binary, however short the file is, or
        a single byte would be enough to change how a script is read. A file
        that starts with ``#!`` is a script whatever else it holds, since
        that is how the kernel runs it. UTF-16 and UTF-32 text is full of
        NUL bytes, so a BOM for either, or the byte pattern of UTF-16,
        counts as text.
        """
        try:
            with open(filepath, "rb") as f:
                chunk = f.read(_BINARY_CHECK_SIZE)
        except OSError:
            # Not known to be binary. scan_file() will fail to read it too,
            # and record that it was not scanned.
            return False
        if chunk.startswith(b"#!") or _detect_bom_encoding(chunk) or _guess_bomless_utf16(chunk):
            return False
        controls = _control_bytes(chunk)
        return controls >= _MIN_CONTROL_BYTES and controls * _TEXT_RATIO > len(chunk)


def _glob_match(path: str, pattern: str) -> bool:
    """Match *path* against an allowlist glob.

    ``*`` and ``?`` stay within one path segment; ``**`` spans any number of
    them, including none. A pattern without a leading ``/`` matches at any
    depth, so ``*.po`` covers ``a/b/c.po``. A trailing ``/`` means everything
    under that directory.

    ``PurePath.match`` is not used because it treats ``**`` like ``*``, and
    ``PurePath.full_match`` needs Python 3.13.
    """
    return _compile_glob(pattern).search(path.replace("\\", "/")) is not None


@functools.lru_cache(maxsize=256)
def _compile_glob(pattern: str) -> re.Pattern[str]:
    pattern = pattern.replace("\\", "/")
    anchored = pattern.startswith("/")
    if pattern.endswith("/"):
        pattern += "**"
    segments = [seg for seg in pattern.split("/") if seg and seg != "."]

    parts: list[str] = []
    for i, seg in enumerate(segments):
        last = i == len(segments) - 1
        if seg == "**":
            parts.append(".*" if last else "(?:[^/]+/)*")
        else:
            parts.append(_translate_glob_segment(seg) + ("" if last else "/"))

    prefix = "^/" if anchored else "(?:^|/)"
    flags = re.IGNORECASE if os.name == "nt" else 0
    return re.compile(prefix + "".join(parts) + "$", flags)


def _translate_glob_segment(segment: str) -> str:
    """Translate one ``/``-free glob segment to a regex fragment."""
    out: list[str] = []
    i = 0
    while i < len(segment):
        ch = segment[i]
        i += 1
        if ch == "*":
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        elif ch == "[":
            # A "]" straight after "[" or "[!" is a literal member of the set.
            start = i + 1 if segment[i : i + 1] == "!" else i
            end = segment.find("]", start + 1)
            if end == -1:
                out.append(re.escape(ch))
                continue
            negate = segment[i] == "!"
            members = segment[i + 1 if negate else i : end]
            members = re.sub(r"([\\^\[&~|])", r"\\\1", members)
            out.append(f"(?!/)[{'^' if negate else ''}{members}]")
            i = end + 1
        else:
            out.append(re.escape(ch))
    return "".join(out)
