"""Core scanner for detecting dangerous invisible Unicode characters."""

from __future__ import annotations

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

IGNORE_COMMENT = "heckler-ignore"

# Pattern requires heckler-ignore to appear after a comment token.
# Matches: // heckler-ignore, # heckler-ignore, /* heckler-ignore */,
#          -- heckler-ignore, ; heckler-ignore
_IGNORE_PATTERN = re.compile(
    r'(?://|#|/\*|--|;)\s*heckler-ignore'
)

_BINARY_CHECK_SIZE = 8192


@dataclass
class Scanner:
    skip_dirs: frozenset[str] = field(default_factory=lambda: DEFAULT_SKIP_DIRS)
    text_extensions: frozenset[str] | None = field(default_factory=lambda: DEFAULT_TEXT_EXTENSIONS)
    severity_threshold: Severity = Severity.LOW
    exclude_patterns: list[str] = field(default_factory=list)
    allow_bom: bool = True
    scan_deps: bool = False
    diff_only: bool = False

    def scan_text(self, text: str, filename: str = "<string>") -> list[Finding]:
        """Scan a text string for dangerous Unicode. The core primitive."""
        findings: list[Finding] = []
        source, package = self._classify_path(filename)

        # Use split('\n') instead of splitlines() — splitlines() treats
        # U+2028/U+2029 as line terminators, consuming them before the regex
        # can detect them.
        for line_num, line in enumerate(text.split('\n'), 1):
            if _IGNORE_PATTERN.search(line):
                continue
            for match in DANGEROUS_UNICODE_RE.finditer(line):
                cp = ord(match.group()[0])
                # BOM at file start is typically legitimate
                if cp == 0xFEFF and line_num == 1 and match.start() == 0 and self.allow_bom:
                    continue
                info = get_char_info(cp)
                if info.severity >= self.severity_threshold:
                    findings.append(Finding.from_match(
                        filepath=filename,
                        line_num=line_num,
                        col=match.start() + 1,
                        cp=cp,
                        info=info,
                        line_content=line,
                        source=source,
                        package=package,
                    ))
        return findings

    def scan_file(self, filepath: Path) -> list[Finding]:
        """Read a file and scan its contents."""
        try:
            raw = filepath.read_bytes()
        except (OSError, PermissionError):
            return []

        # Check for null bytes — scan text before the first null instead
        # of skipping the entire file (prevents null-byte injection bypass)
        null_pos = raw.find(b'\x00')
        if null_pos != -1:
            if null_pos == 0:
                return []  # Truly binary (starts with null)
            # Scan the portion before the null byte
            raw = raw[:null_pos]

        try:
            text = raw.decode('utf-8', errors='replace')
        except Exception:
            return []
        return self.scan_text(text, str(filepath))

    def scan_path(self, root: Path) -> list[Finding]:
        """Recursively scan a directory or single file."""
        if root.is_file():
            return self.scan_file(root)

        all_findings: list[Finding] = []
        effective_skip = self._effective_skip_dirs()
        effective_exts = self.text_extensions

        for dirpath, dirnames, filenames in os.walk(root):
            # Filter directories in-place
            dirnames[:] = [
                d for d in dirnames
                if d not in effective_skip
            ]
            dp = Path(dirpath)
            # Use restricted extensions for dependency directories
            exts = self._extensions_for_path(dp, effective_exts)
            for fname in filenames:
                fpath = dp / fname
                if self._is_excluded(fpath):
                    continue
                has_ext = bool(fpath.suffix)
                if exts is None or (has_ext and fpath.suffix.lower() in exts) or (not has_ext and fname in KNOWN_FILENAMES):
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
                'node_modules', 'vendor', 'site-packages',
                '.venv', 'venv',
                'target',  # Rust/Cargo build + deps
                'build', 'dist',  # Common build output dirs nested in deps
            }
            return self.skip_dirs - dep_dirs
        return self.skip_dirs

    def _extensions_for_path(
        self, dirpath: Path, default_exts: frozenset[str] | None,
    ) -> frozenset[str] | None:
        """Use restricted extensions inside dependency directories."""
        parts = set(dirpath.parts)
        dep_markers = {'node_modules', 'vendor', 'site-packages', 'target'}
        if parts & dep_markers:
            return DEP_SCAN_EXTENSIONS
        return default_exts

    def _classify_path(self, filepath: str) -> tuple[str, str | None]:
        """Determine if a file is project code or a dependency, and extract package name."""
        parts = filepath.replace('\\', '/').split('/')
        if 'node_modules' in parts:
            idx = parts.index('node_modules')
            if idx + 1 < len(parts):
                pkg = parts[idx + 1]
                # Handle scoped packages: @scope/name
                if pkg.startswith('@') and idx + 2 < len(parts):
                    pkg = f"{pkg}/{parts[idx + 2]}"
                return "dependency", pkg
        if 'site-packages' in parts:
            idx = parts.index('site-packages')
            if idx + 1 < len(parts):
                return "dependency", parts[idx + 1]
        if 'vendor' in parts:
            idx = parts.index('vendor')
            if idx + 1 < len(parts):
                return "dependency", parts[idx + 1]
        return "project", None

    def _is_excluded(self, filepath: Path) -> bool:
        """Check if a file matches any exclude pattern."""
        fp_str = str(filepath)
        return any(_glob_match(fp_str, pattern) for pattern in self.exclude_patterns)

    @staticmethod
    def _is_binary(filepath: Path) -> bool:
        """Check if a file is binary by looking for null bytes."""
        try:
            with open(filepath, 'rb') as f:
                chunk = f.read(_BINARY_CHECK_SIZE)
                return b'\x00' in chunk
        except (OSError, PermissionError):
            return True


def _glob_match(path: str, pattern: str) -> bool:
    """Glob matching for exclude patterns, supporting ** patterns."""
    from pathlib import PurePath
    # PurePath.match handles ** (recursive) patterns correctly
    return PurePath(path).match(pattern)
