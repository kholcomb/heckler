"""Configuration loading for heckler.

Loads from: --config flag → .heckler.yml → [tool.heckler] in pyproject.toml → defaults.
Zero external dependencies — includes a minimal YAML parser for the flat config format,
and a reader for the [tool.heckler] table for the Python versions that have no TOML parser.
"""

from __future__ import annotations

import contextlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .characters import Severity
from .formatters.text import spell_out
from .scanner import DEFAULT_SKIP_DIRS, DEFAULT_TEXT_EXTENSIONS


@dataclass
class Config:
    skip_dirs: frozenset[str] = field(default_factory=lambda: DEFAULT_SKIP_DIRS)
    text_extensions: frozenset[str] = field(default_factory=lambda: DEFAULT_TEXT_EXTENSIONS)
    severity_threshold: Severity = Severity.LOW
    exclude_patterns: list[str] = field(default_factory=list)
    allow_bom: bool = True
    scan_deps: bool = False
    allow_emoji: bool = True

    @staticmethod
    def defaults() -> Config:
        return Config()


def load_config(
    config_path: str | None = None,
    scan_deps: bool = False,
) -> Config:
    """Load configuration from file, falling back to defaults."""
    raw: dict[str, object] = {}

    if config_path:
        p = Path(config_path)
        if p.exists():
            raw = _load_yaml_file(p)
        else:
            raise FileNotFoundError(f"Config file not found: {config_path}")
    else:
        # Auto-discover
        for candidate in (".heckler.yml", ".heckler.yaml"):
            p = Path(candidate)
            if p.exists():
                raw = _load_yaml_file(p)
                break
        else:
            # Try pyproject.toml
            raw = _load_pyproject_section()

    config = Config.defaults()

    if "severity" in raw:
        sev_str = str(raw["severity"]).upper()
        with contextlib.suppress(KeyError):
            config.severity_threshold = Severity[sev_str]

    if "allowlist" in raw and isinstance(raw["allowlist"], list):
        config.exclude_patterns = [str(p) for p in raw["allowlist"]]

    if "allow_bom" in raw:
        config.allow_bom = bool(raw["allow_bom"])

    if "allow_emoji" in raw:
        config.allow_emoji = bool(raw["allow_emoji"])

    if "extra_skip_dirs" in raw and isinstance(raw["extra_skip_dirs"], list):
        config.skip_dirs = config.skip_dirs | frozenset(str(d) for d in raw["extra_skip_dirs"])

    if "extra_extensions" in raw and isinstance(raw["extra_extensions"], list):
        config.text_extensions = config.text_extensions | frozenset(
            str(e) if e.startswith(".") else f".{e}" for e in raw["extra_extensions"]
        )

    config.scan_deps = scan_deps

    return config


def _load_yaml_file(path: Path) -> dict[str, object]:
    """Load a YAML file. Tries PyYAML first, falls back to minimal parser."""
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore[import-untyped]

        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}
    except ImportError:
        return _minimal_yaml_parse(text)


def _load_pyproject_section() -> dict[str, object]:
    """Load [tool.heckler] from pyproject.toml."""
    pyproject = Path("pyproject.toml")
    if not pyproject.exists():
        return {}
    try:
        # Python 3.11+
        import tomllib  # type: ignore[import-not-found]

        with open(pyproject, "rb") as f:
            data = tomllib.load(f)
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[import-not-found]

            with open(pyproject, "rb") as f:
                data = tomllib.load(f)
        except ImportError:
            # Python 3.9 or 3.10 without tomli.
            settings, unreadable = _read_tool_table(pyproject.read_text(encoding="utf-8"))
            for line in unreadable:
                print(
                    "Warning: pyproject.toml: this [tool.heckler] line could not be read"
                    f" and was ignored: {spell_out(line)}\n"
                    "  This Python has no TOML parser. Install tomli, or move the"
                    " settings to .heckler.yml.",
                    file=sys.stderr,
                )
            return settings
    tool: dict[str, object] = data.get("tool", {})
    if not isinstance(tool, dict):
        return {}
    result = tool.get("heckler", {})
    return result if isinstance(result, dict) else {}


# ---------------------------------------------------------------------------
# [tool.heckler] without a TOML library
# ---------------------------------------------------------------------------
#
# tomllib arrived in Python 3.11. On 3.9 and 3.10, unless tomli happens to be
# installed, there is nothing to read pyproject.toml with, and silently
# falling back to the defaults would drop a project's allowlist or severity
# without a word. The settings table is flat, so a small reader covers it:
# strings, booleans, integers, and arrays of those, on one line or several.
# A line it cannot read is returned for the caller to warn about.

_TOML_TABLE_RE = re.compile(r"^\s*\[")
_TOML_HECKLER_TABLE_RE = re.compile(r"^\s*\[\s*tool\s*\.\s*heckler\s*\]\s*(?:#.*)?$")
_TOML_KEY_RE = re.compile(r"^\s*([A-Za-z0-9_-]+)\s*=\s*(.*)$")
_TOML_TOKEN_RE = re.compile(
    r"""\s*(?:
        (?P<basic>"(?:[^"\\\n]|\\.)*")     # "basic string", with escapes
      | (?P<literal>'[^'\n]*')             # 'literal string', taken as written
      | (?P<word>[A-Za-z0-9_.+-]+)         # true, false, a number
      | (?P<punct>[\[\],])
      | (?P<comment>\#[^\n]*)
    )""",
    re.VERBOSE,
)
_TOML_STRING_DECODER = json.JSONDecoder(strict=False)


def _toml_tokens(text: str) -> list[tuple[str, str]] | None:
    """Split a TOML value into ``(kind, text)`` tokens, or None if it is not all tokens."""
    tokens: list[tuple[str, str]] = []
    pos = 0
    while text[pos:].strip():
        m = _TOML_TOKEN_RE.match(text, pos)
        if not m or not m.lastgroup:
            return None
        pos = m.end()
        if m.lastgroup != "comment":
            tokens.append((m.lastgroup, m.group(m.lastgroup)))
    return tokens


def _toml_scalar(kind: str, text: str) -> object:
    if kind == "basic":
        # The escapes of a TOML basic string are, for anything a settings
        # table holds, those of a JSON string. Others raise ValueError.
        return _TOML_STRING_DECODER.decode(text)
    if kind == "literal":
        return text[1:-1]
    if kind == "word":
        if text in ("true", "false"):
            return text == "true"
        if re.fullmatch(r"[+-]?[0-9]+", text):
            return int(text)
    raise ValueError(text)


def _toml_value(tokens: list[tuple[str, str]]) -> object:
    """Turn the tokens of one value into a Python object; ValueError if they are not one."""
    if len(tokens) == 1:
        return _toml_scalar(*tokens[0])
    if len(tokens) < 2 or tokens[0] != ("punct", "[") or tokens[-1] != ("punct", "]"):
        raise ValueError
    items: list[object] = []
    want_item = True
    for kind, text in tokens[1:-1]:
        if (kind, text) == ("punct", ","):
            if want_item:
                raise ValueError
            want_item = True
        elif not want_item:
            raise ValueError
        else:
            items.append(_toml_scalar(kind, text))  # a nested "[" raises here
            want_item = False
    return items


def _read_tool_table(text: str) -> tuple[dict[str, object], list[str]]:
    """Read ``[tool.heckler]`` from the text of a pyproject.toml.

    Returns the settings and the lines of the table that could not be read.
    """
    settings: dict[str, object] = {}
    unreadable: list[str] = []
    lines = text.splitlines()
    inside = False
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if _TOML_TABLE_RE.match(line):
            inside = _TOML_HECKLER_TABLE_RE.match(line) is not None
            continue
        if not inside or not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _TOML_KEY_RE.match(line)
        if not m:
            unreadable.append(line.strip())
            continue
        key, value = m.group(1), m.group(2)
        tokens = _toml_tokens(value)
        # An array may run over several lines: read on until it closes.
        while tokens is not None and _toml_open_arrays(tokens) > 0 and i < len(lines):
            value += "\n" + lines[i]
            i += 1
            tokens = _toml_tokens(value)
        try:
            if tokens is None:
                raise ValueError
            settings[key] = _toml_value(tokens)
        except ValueError:
            unreadable.append(line.strip())
    return settings, unreadable


def _toml_open_arrays(tokens: list[tuple[str, str]]) -> int:
    return tokens.count(("punct", "[")) - tokens.count(("punct", "]"))


def _strip_inline_comment(value: str) -> str:
    """Drop a trailing ``# comment`` from a YAML value.

    As in YAML, ``#`` starts a comment only after whitespace, and never
    inside a quoted string.
    """
    quote = ""
    for i, ch in enumerate(value):
        prev = value[i - 1] if i else " "
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'" and (prev.isspace() or prev in "[,"):
            quote = ch
        elif ch == "#" and prev.isspace():
            return value[:i].rstrip()
    return value


def _minimal_yaml_parse(text: str) -> dict[str, object]:
    """Parse a flat YAML config file with no external dependencies.

    Handles: key: value, key: [list], and indented list items (- item).
    Sufficient for .heckler.yml which is intentionally flat.
    """
    result: dict[str, object] = {}
    current_key: str | None = None
    current_list: list[str] | None = None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # List item under a key
        if stripped.startswith("- ") and current_key is not None:
            if current_list is None:
                current_list = []
            val = _strip_inline_comment(stripped[2:].strip()).strip('"').strip("'")
            current_list.append(val)
            result[current_key] = current_list
            continue

        # Key: value pair
        m = re.match(r"^(\w[\w_-]*)\s*:\s*(.*)", stripped)
        if m:
            # Save previous list
            key = m.group(1)
            val_str = _strip_inline_comment(m.group(2).strip())

            current_key = key
            current_list = None

            if not val_str:
                # Could be a list or nested dict following
                result[key] = []
                current_list = []
            elif val_str == "[]":
                result[key] = []
                current_list = []
            elif val_str.lower() in ("true", "yes"):
                result[key] = True
            elif val_str.lower() in ("false", "no"):
                result[key] = False
            elif val_str.startswith("[") and val_str.endswith("]"):
                # Inline list
                items = [
                    i.strip().strip('"').strip("'") for i in val_str[1:-1].split(",") if i.strip()
                ]
                result[key] = items
            else:
                result[key] = val_str.strip('"').strip("'")
        else:
            current_key = None
            current_list = None

    return result
