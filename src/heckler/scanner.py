"""Core scanner for detecting dangerous invisible Unicode characters."""

from __future__ import annotations

import functools
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .characters import (
    _KEYCAP_BASES,
    _ZERO_WIDTH_JOINER,
    DANGEROUS_UNICODE_RE,
    PRESENTATION_SELECTORS,
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

# Well-known files without extensions that should be scanned
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

# Restricted set for dependency scanning — source files that could execute
# or be imported as code. Broader than just "executable" to cover compiled
# language ecosystems (Rust, Go, Java, etc.) where deps contain source.
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

# Directives are found by pattern; heckler does not parse the 60-odd languages
# it scans. Three rules keep text that only looks like a directive from
# working as one:
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
# Scanner.skipped, because a file nobody looked at is not a clean one.
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

# The second reading of a file whose byte order mark is believed reports
# nothing below this code point. See Scanner.scan_file().
_BELIEVED_BOM_FLOOR = 0xA0


def _control_bytes(data: bytes) -> int:
    """How many bytes of *data* are control characters that text does not hold."""
    return len(data) - len(data.translate(None, _CONTROL_BYTES))


def _is_utf8_text(data: bytes) -> bool:
    """False if too much of *data* is control bytes or invalid UTF-8 to be text.

    It takes a share of the bytes to say so. A single NUL proves nothing:
    putting one in a comment costs one byte.
    """
    invalid = data.decode("utf-8", errors="replace").count(_REPLACEMENT)
    return (_control_bytes(data) + invalid) * _TEXT_RATIO <= len(data)


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


def _other_readings(raw: bytes, bom_codec: str | None, believed: bool) -> list[tuple[str, int]]:
    """What to scan a file as besides the encoding it presents itself in.

    Each reading is a codec and the lowest code point to report from it.
    *believed* says whether the content matches *bom_codec*.
    """
    if bom_codec is None:
        head = raw[:_BINARY_CHECK_SIZE]
        guess = _guess_bomless_utf32(head) or _guess_bomless_utf16(head, _UTF16_HIGH_BYTES)
        return [(guess, 0)] if guess else []
    if believed:
        return [("utf-8", _BELIEVED_BOM_FLOOR)]
    if bom_codec == "utf-32-le":
        # FF FE 00 00 is also the UTF-16 BOM followed by a NUL character.
        return [("utf-8", 0), ("utf-16-le", 0)]
    return [("utf-8", 0)]


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


def _label_reading(findings: list[Finding], codec: str) -> None:
    """Mark findings as coming from one of several decodings of a file."""
    for finding in findings:
        finding.char_name = f"{finding.char_name} (read as {_ENCODING_LABELS[codec]})"


def _is_script(filepath: Path) -> bool:
    """True if the file starts with ``#!``, which makes it a script whatever it is called."""
    try:
        with open(filepath, "rb") as f:
            return f.read(2) == b"#!"
    except OSError:
        return False


def _is_known_name(name: str) -> bool:
    """True for a file name that is scanned whatever its extension."""
    return name in KNOWN_FILENAMES or name.startswith(KNOWN_FILENAME_PREFIXES)


@dataclass
class Scanner:
    skip_dirs: frozenset[str] = field(default_factory=lambda: DEFAULT_SKIP_DIRS)
    text_extensions: frozenset[str] | None = field(default_factory=lambda: DEFAULT_TEXT_EXTENSIONS)
    severity_threshold: Severity = Severity.LOW
    exclude_patterns: list[str] = field(default_factory=list)
    allow_bom: bool = True
    scan_deps: bool = False
    diff_only: bool = False
    allow_emoji: bool = True
    # False ignores heckler-ignore directives, to list what they are hiding.
    honor_directives: bool = True

    # What the scans so far left out or held back, for the caller to report.
    #: ``(path, reason)`` for each file or directory that could not be scanned.
    skipped: list[tuple[str, str]] = field(
        default_factory=list, init=False, repr=False, compare=False
    )
    #: Number of findings a directive suppressed, by file.
    suppressed: dict[str, int] = field(default_factory=dict, init=False, repr=False, compare=False)
    #: Findings reported from a line whose directive lists no codepoints.
    unlisted: int = field(default=0, init=False, repr=False, compare=False)
    #: Directories that were not entered because of their name, other than
    #: version control data and tool caches.
    skipped_dirs: list[str] = field(default_factory=list, init=False, repr=False, compare=False)
    #: Files left out because they hold too many control bytes to be text.
    #: Only a scan without an extension list decides that from the content.
    binary: list[str] = field(default_factory=list, init=False, repr=False, compare=False)

    def scan_text(self, text: str, filename: str = "<string>") -> list[Finding]:
        """Scan a text string for dangerous Unicode. The core primitive."""
        return self._scan_text(text, filename, 0)

    def _scan_text(self, text: str, filename: str, floor: int) -> list[Finding]:
        """scan_text(), reporting only code points from *floor* up."""
        findings: list[Finding] = []
        source, package = self._classify_path(filename)
        # Never honor suppression directives in dependency code —
        # a malicious package author could embed them to hide attacks.
        honor = self.honor_directives and source != "dependency" and not self.scan_deps
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
            if honor:
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
            for match in DANGEROUS_UNICODE_RE.finditer(line):
                cp = ord(match.group()[0])
                if cp < floor:
                    continue
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
                        if base not in _KEYCAP_BASES:  # or every digit would count as bare
                            styled[(base, cp)] = styled.get((base, cp), 0) + 1
                            first_styled = first_styled or (line_num, match.start(), line)
                    elif cp == _ZERO_WIDTH_JOINER:
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
                _ZERO_WIDTH_JOINER,
                CharInfo(
                    f"{joiners} zero width joiners between emoji in this file",
                    ThreatCategory.ZERO_WIDTH,
                    Severity.LOW,
                ),
            )
        return findings

    @staticmethod
    def _stopped_early(findings: list[Finding], filename: str) -> list[Finding]:
        print(
            f"Warning: {filename}: stopped after {_MAX_FINDINGS_PER_FILE}"
            " findings; the rest of the file was not scanned.",
            file=sys.stderr,
        )
        return findings

    def scan_file(self, filepath: Path) -> list[Finding]:
        """Read a file and scan its contents.

        A file that cannot be read, or is too large to, yields no findings
        and is recorded in ``skipped``.
        """
        name = str(filepath)
        try:
            size = filepath.stat().st_size
            if size > _MAX_SCAN_FILE_SIZE:
                limit = _MAX_SCAN_FILE_SIZE // (1024 * 1024)
                self.skipped.append((name, f"it is larger than {limit} MB"))
                return []
            raw = filepath.read_bytes()
        except OSError as e:
            self.skipped.append((name, f"it could not be read ({e.strerror or e})"))
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
        # file is worth scanning at all is decided by the caller, from its
        # name.
        bom_codec = _detect_bom_encoding(raw)
        findings = self.scan_text(raw.decode(bom_codec or "utf-8", errors="replace"), name)

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
            _label_reading(findings, bom_codec)
            findings[:0] = self._bom_mismatch(name, bom_codec)
        for codec, floor in _other_readings(raw, bom_codec, believed):
            reading = self._scan_text(raw.decode(codec, errors="replace"), name, floor)
            _label_reading(reading, codec)
            findings.extend(reading)
        return findings

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

    def scan_path(self, root: Path) -> list[Finding]:
        """Recursively scan a directory or single file."""
        if root.is_file():
            # A file named on the command line (which is how pre-commit passes
            # them) still honours the allowlist, so .heckler.yml means the
            # same thing whether heckler walks a directory or is handed files.
            if self._is_excluded(root):
                return []
            return self.scan_file(root)
        if not root.is_dir():
            reason = "it is not a file or a directory" if root.exists() else "it does not exist"
            self.skipped.append((str(root), reason))
            return []

        all_findings: list[Finding] = []
        effective_skip = self._effective_skip_dirs()
        effective_exts = self.text_extensions

        def unreadable(error: OSError) -> None:
            reason = f"the directory could not be read ({error.strerror or error})"
            self.skipped.append((str(error.filename or root), reason))

        for dirpath, dirnames, filenames in os.walk(root, onerror=unreadable, followlinks=False):
            # Filter directories in-place — skip symlinks and excluded dirs.
            # Sorted, here and below, so the report comes out in the same
            # order on every filesystem.
            entered = []
            for d in sorted(dirnames):
                path = os.path.join(dirpath, d)
                if d in effective_skip:
                    if d not in _NEVER_SCANNED_DIRS:
                        self.skipped_dirs.append(path)
                elif not os.path.islink(path):
                    entered.append(d)
            dirnames[:] = entered
            dp = Path(dirpath)
            # Use restricted extensions for dependency directories
            exts = self._extensions_for_path(dp, effective_exts)
            for fname in sorted(filenames):
                fpath = dp / fname
                if os.path.islink(fpath) or self._is_excluded(fpath):
                    continue
                if exts is None:
                    wanted = self.is_text_file(fpath)
                    if not wanted:
                        self.binary.append(str(fpath))
                elif exts is DEP_SCAN_EXTENSIONS:
                    wanted = self.is_dependency_source(fpath)
                else:
                    wanted = (
                        fpath.suffix.lower() in exts or _is_known_name(fname) or _is_script(fpath)
                    )
                if wanted:
                    all_findings.extend(self.scan_file(fpath))
        return all_findings

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

    def _extensions_for_path(
        self,
        dirpath: Path,
        default_exts: frozenset[str] | None,
    ) -> frozenset[str] | None:
        """Use restricted extensions inside dependency directories."""
        if default_exts is None:
            # --all-text means every text file, in a dependency as elsewhere.
            return None
        parts = set(dirpath.parts)
        dep_markers = {"node_modules", "vendor", "site-packages", "target"}
        if parts & dep_markers:
            return DEP_SCAN_EXTENSIONS
        return default_exts

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
    def is_text_file(filepath: Path) -> bool:
        """Whether a file is scanned when there is no extension list to go by.

        Content is then the only way to leave out images, archives and the
        like. A recognised source name is always scanned, so a NUL byte
        cannot be used to opt such a file out.
        """
        return Scanner._is_source_name(filepath) or not Scanner._is_binary(filepath)

    @staticmethod
    def is_dependency_source(filepath: Path) -> bool:
        """Whether a file inside a dependency is scanned when there is an extension list.

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
    def _is_source_name(filepath: Path) -> bool:
        """True if the name alone marks the file as one heckler scans by default."""
        return filepath.suffix.lower() in DEFAULT_TEXT_EXTENSIONS or _is_known_name(filepath.name)

    @staticmethod
    def _is_binary(filepath: Path) -> bool:
        """Whether the start of a file is too full of control bytes to be text.

        One NUL does not make a file binary, or a single byte would be
        enough to opt a script out of the scan. A file that starts with
        ``#!`` is a script whatever else it holds, since that is how the
        kernel runs it. UTF-16 and UTF-32 text is full of NUL bytes, so a
        BOM for either, or the byte pattern of UTF-16, counts as text.
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
        return _control_bytes(chunk) * _TEXT_RATIO > len(chunk)


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
