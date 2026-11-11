"""Core scanner for detecting dangerous invisible Unicode characters."""

from __future__ import annotations

import functools
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .characters import (
    DANGEROUS_UNICODE_RE,
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
    '.js', '.cjs', '.mjs', '.ts', '.jsx', '.tsx', '.py', '.pyi', '.rb', '.go',
    '.rs', '.c', '.cpp', '.h', '.hpp', '.java', '.cs', '.php', '.sh', '.bash',
    '.zsh', '.yaml', '.yml', '.json', '.toml', '.xml', '.html', '.css', '.scss',
    '.sql', '.swift', '.kt', '.scala', '.lua', '.pl', '.r', '.md', '.txt',
    '.cfg', '.ini', '.dockerfile', '.tf', '.hcl', '.vue', '.svelte',
    # Shells
    '.ps1', '.bat', '.cmd', '.fish',
    # Templates
    '.ejs', '.hbs', '.njk', '.pug', '.jinja',
    # Build systems
    '.gradle', '.rake', '.cmake', '.mk',
    # Schema/IDL
    '.graphql', '.gql', '.proto',
    # Config
    '.env.example', '.conf', '.properties',
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
    'Dockerfile',
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
})

DEFAULT_SKIP_DIRS = frozenset({
    'node_modules', 'vendor', '.git', '__pycache__', '.venv', 'venv',
    'dist', 'build', 'target', '.next', '.nuxt', 'coverage',
    'site-packages', '.tox', '.eggs', '.mypy_cache', '.ruff_cache',
})

# Restricted set for dependency scanning — source files that could execute
# or be imported as code. Broader than just "executable" to cover compiled
# language ecosystems (Rust, Go, Java, etc.) where deps contain source.
DEP_SCAN_EXTENSIONS = frozenset({
    '.js', '.cjs', '.mjs', '.ts', '.jsx', '.tsx',  # JavaScript/TypeScript
    '.py', '.pyi',                                   # Python
    '.sh', '.bash',                                  # Shell
    '.rb',                                            # Ruby
    '.php',                                           # PHP
    '.go',                                            # Go
    '.pl',                                            # Perl
    '.rs',                                            # Rust
    '.java', '.kt', '.scala', '.groovy',             # JVM
    '.cs',                                            # C# / .NET
    '.swift',                                         # Swift
    '.c', '.cpp', '.h', '.hpp',                      # C/C++
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

IGNORE_COMMENT = "heckler-ignore"

# Next-line suppression directive with optional codepoint list.
# Must appear on its own line (only whitespace + comment token before it).
# Format:  // heckler-ignore-next-line [U+XXXX U+YYYY ...]
#          # heckler-ignore-next-line U+FE0F
# The codepoints listed are the ONLY ones suppressed on the next line.
# If no codepoints are listed, all findings on the next line are suppressed.
_IGNORE_NEXT_LINE_RE = re.compile(
    r"^\s*(?://|#|/\*|--|;)\s*heckler-ignore-next-line"
    r"(?:\s+((?:U\+[0-9A-Fa-f]{4,6}\s*)+))?"
    r"\s*(?:\*/\s*)?$"
)

# Legacy inline directive (end-of-line anchor prevents mid-string injection).
# Deprecated in favor of heckler-ignore-next-line but still supported for
# project code. Never honored in dependency code.
_IGNORE_INLINE_RE = re.compile(
    r"(?://|#|/\*|--|;)\s*heckler-ignore"
    r"(?:\s+((?:U\+[0-9A-Fa-f]{4,6}\s*)+))?"
    r"\s*(?:\*/\s*)?$"
)

_CODEPOINT_RE = re.compile(r"U\+([0-9A-Fa-f]{4,6})")


def _parse_suppressed_codepoints(directive_match: re.Match[str]) -> frozenset[int] | None:
    """Extract codepoints from a suppression directive.

    Returns a frozenset of codepoint ints, or None meaning "suppress all".
    """
    cp_str = directive_match.group(1)
    if not cp_str:
        return None  # no codepoints listed → suppress all
    return frozenset(int(m.group(1), 16) for m in _CODEPOINT_RE.finditer(cp_str))


_BINARY_CHECK_SIZE = 8192

# Maximum file size to scan (50 MB). Files larger than this are skipped to
# prevent memory exhaustion from adversarially large inputs.
_MAX_SCAN_FILE_SIZE = 50 * 1024 * 1024

# BOM signatures ordered longest-first so UTF-32 is checked before UTF-16.
_BOM_TABLE: list[tuple[bytes, str]] = [
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
]


def _detect_bom_encoding(raw: bytes) -> str | None:
    """Return the codec name if *raw* starts with a UTF-16/32 BOM."""
    for sig, codec in _BOM_TABLE:
        if raw[: len(sig)] == sig:
            return codec
    return None


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

    def scan_text(self, text: str, filename: str = "<string>") -> list[Finding]:
        """Scan a text string for dangerous Unicode. The core primitive."""
        findings: list[Finding] = []
        source, package = self._classify_path(filename)
        is_dependency = source == "dependency" or self.scan_deps

        # Use split('\n') instead of splitlines() — splitlines() treats
        # U+2028/U+2029 as line terminators, consuming them before the regex
        # can detect them.
        lines = text.split("\n")
        # Suppressed codepoints for the next line (from heckler-ignore-next-line).
        # None means "suppress all", a frozenset means "suppress only these".
        _NO_SUPPRESS: frozenset[int] = frozenset()
        next_line_suppress: frozenset[int] | None = _NO_SUPPRESS

        for line_num, line in enumerate(lines, 1):
            # Determine suppression for this line
            suppress: frozenset[int] | None = next_line_suppress
            next_line_suppress = _NO_SUPPRESS

            # Never honor suppression directives in dependency code —
            # a malicious package author could embed them to hide attacks.
            if not is_dependency:
                # Check for next-line directive (applies to the NEXT line)
                nl_match = _IGNORE_NEXT_LINE_RE.match(line)
                if nl_match:
                    next_line_suppress = _parse_suppressed_codepoints(nl_match)
                    continue  # directive line itself is not scanned

                # Legacy inline directive (end-of-line anchored)
                inline_match = _IGNORE_INLINE_RE.search(line)
                if inline_match:
                    suppress = _parse_suppressed_codepoints(inline_match)

            for match in DANGEROUS_UNICODE_RE.finditer(line):
                cp = ord(match.group()[0])
                # BOM at file start is typically legitimate
                if cp == 0xFEFF and line_num == 1 and match.start() == 0 and self.allow_bom:
                    continue
                # Check suppression: None = all, non-empty frozenset = specific
                if suppress is None or cp in suppress:
                    continue
                info = get_char_info(cp)
                if self.allow_emoji and is_emoji_context(line, match.start()):
                    # Part of a well-formed emoji. Still reported, but at
                    # INFO, which is below every default threshold.
                    info = CharInfo(f"{info.name} (in emoji)", info.category, Severity.INFO)
                if info.severity >= self.severity_threshold:
                    findings.append(
                        Finding.from_match(
                            filepath=filename,
                            line_num=line_num,
                            col=match.start() + 1,
                            cp=cp,
                            info=info,
                            line_content=line,
                            source=source,
                            package=package,
                        )
                    )
        return findings

    def scan_file(self, filepath: Path) -> list[Finding]:
        """Read a file and scan its contents."""
        try:
            size = filepath.stat().st_size
            if size > _MAX_SCAN_FILE_SIZE:
                return []
            raw = filepath.read_bytes()
        except (OSError, PermissionError):
            return []

        # Detect non-UTF-8 encodings via BOM signatures.  UTF-16/32 files
        # contain embedded null bytes that would otherwise cause the scanner
        # to treat them as binary and skip the content entirely — an attacker
        # could exploit this by committing a UTF-16 encoded file.
        encoding = _detect_bom_encoding(raw)
        if encoding:
            try:
                text = raw.decode(encoding, errors="replace")
                return self.scan_text(text, str(filepath))
            except Exception:
                return []

        # UTF-8 path. A NUL byte does not end the scan: JavaScript accepts
        # one inside a comment, PHP before its opening tag, and bash after
        # the first line, so stopping there would let a single byte hide
        # everything that follows it. Whether a file is worth scanning at all
        # is decided by the caller, from its name.
        text = raw.decode("utf-8", errors="replace")
        return self.scan_text(text, str(filepath))

    def scan_path(self, root: Path) -> list[Finding]:
        """Recursively scan a directory or single file."""
        if root.is_file():
            # A file named on the command line (which is how pre-commit passes
            # them) still honours the allowlist, so .heckler.yml means the
            # same thing whether heckler walks a directory or is handed files.
            if self._is_excluded(root):
                return []
            return self.scan_file(root)

        all_findings: list[Finding] = []
        effective_skip = self._effective_skip_dirs()
        effective_exts = self.text_extensions

        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            # Filter directories in-place — skip symlinks and excluded dirs
            dirnames[:] = [
                d
                for d in dirnames
                if d not in effective_skip and not os.path.islink(os.path.join(dirpath, d))
            ]
            dp = Path(dirpath)
            # Use restricted extensions for dependency directories
            exts = self._extensions_for_path(dp, effective_exts)
            for fname in filenames:
                fpath = dp / fname
                if os.path.islink(fpath) or self._is_excluded(fpath):
                    continue
                has_ext = bool(fpath.suffix)
                if exts is None:
                    # Scanning everything: with no extension filter, content
                    # is the only way to leave out images, archives and the
                    # like. A recognised source name is always scanned, so a
                    # NUL byte cannot be used to opt such a file out.
                    if self._is_source_name(fpath) or not self._is_binary(fpath):
                        all_findings.extend(self.scan_file(fpath))
                    continue
                ext_match = has_ext and fpath.suffix.lower() in exts
                name_match = not has_ext and fname in KNOWN_FILENAMES
                if ext_match or name_match:
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
            # Remove dependency dirs from skip list when scanning deps
            dep_dirs = {
                "node_modules",
                "vendor",
                "site-packages",
                ".venv",
                "venv",
                "target",  # Rust/Cargo build + deps
                "build",
                "dist",  # Common build output dirs nested in deps
            }
            return self.skip_dirs - dep_dirs
        return self.skip_dirs

    def _extensions_for_path(
        self,
        dirpath: Path,
        default_exts: frozenset[str] | None,
    ) -> frozenset[str] | None:
        """Use restricted extensions inside dependency directories."""
        parts = set(dirpath.parts)
        dep_markers = {"node_modules", "vendor", "site-packages", "target"}
        if parts & dep_markers:
            return DEP_SCAN_EXTENSIONS
        return default_exts

    def _classify_path(self, filepath: str) -> tuple[str, str | None]:
        """Determine if a file is project code or a dependency, and extract package name."""
        parts = filepath.replace("\\", "/").split("/")
        if "node_modules" in parts:
            idx = parts.index("node_modules")
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
    def _is_source_name(filepath: Path) -> bool:
        """True if the name alone marks the file as one heckler scans by default."""
        return (
            filepath.suffix.lower() in DEFAULT_TEXT_EXTENSIONS or filepath.name in KNOWN_FILENAMES
        )

    @staticmethod
    def _is_binary(filepath: Path) -> bool:
        """Check if a file is binary by looking for null bytes.

        UTF-16 and UTF-32 text is full of them, so a BOM for either counts
        as text.
        """
        try:
            with open(filepath, "rb") as f:
                chunk = f.read(_BINARY_CHECK_SIZE)
        except (OSError, PermissionError):
            return True
        return _detect_bom_encoding(chunk) is None and b"\x00" in chunk


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
