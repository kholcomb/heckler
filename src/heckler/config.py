"""Configuration loading for heckler.

Settings come from the --config file, else .heckler.yml, else [tool.heckler]
in pyproject.toml, else the defaults.

.heckler.yml is read by the small reader below and by nothing else, so the
file means the same thing wherever heckler runs. A YAML library reads more
of YAML than this does, and using one where it happens to be installed made
one file mean two things. What the reader does not cover, and a value that
a setting cannot take, is an error: settings that were half read could
switch off part of a scan without a word.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .characters import Severity
from .formatters.text import spell_out
from .scanner import DEFAULT_SKIP_DIRS, DEFAULT_TEXT_EXTENSIONS


class ConfigError(ValueError):
    """A configuration file that cannot be used as it is written."""


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
    """Load configuration from file, falling back to defaults.

    Raises FileNotFoundError for a *config_path* that does not exist, and
    ConfigError for a file that cannot be used as it is written.
    """
    raw: dict[str, object] = {}
    source = ""

    if config_path:
        p = Path(config_path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
        raw, source = _load_yaml_file(p), config_path
    else:
        # Auto-discover
        for candidate in (".heckler.yml", ".heckler.yaml"):
            p = Path(candidate)
            if p.exists():
                raw, source = _load_yaml_file(p), candidate
                break
        else:
            raw, source = _load_pyproject_section(), "pyproject.toml, [tool.heckler]"

    config = Config.defaults()

    if "severity" in raw:
        config.severity_threshold = _severity(raw["severity"], source)

    if "allowlist" in raw:
        config.exclude_patterns = _strings(raw, "allowlist", source)

    if "allow_bom" in raw:
        config.allow_bom = _boolean(raw, "allow_bom", source)

    if "allow_emoji" in raw:
        config.allow_emoji = _boolean(raw, "allow_emoji", source)

    if "extra_skip_dirs" in raw:
        config.skip_dirs = config.skip_dirs | frozenset(_strings(raw, "extra_skip_dirs", source))

    if "extra_extensions" in raw:
        config.text_extensions = config.text_extensions | frozenset(
            e if e.startswith(".") else f".{e}" for e in _strings(raw, "extra_extensions", source)
        )

    config.scan_deps = scan_deps

    return config


# A setting with a value of the wrong kind is refused, not coerced. bool()
# of any non-empty string is True, so "allow_bom: off" taken as a string
# would switch the BOM check off, and an unknown severity that fell back to
# the default would go unnoticed.


def _severity(value: object, source: str) -> Severity:
    if isinstance(value, str) and value.upper() in Severity.__members__:
        return Severity[value.upper()]
    names = ", ".join(severity.value for severity in Severity)
    raise ConfigError(f"{source}: severity must be one of {names}, not {value!r}")


def _boolean(raw: dict[str, object], key: str, source: str) -> bool:
    value = raw[key]
    if isinstance(value, bool):
        return value
    raise ConfigError(f"{source}: {key} must be true or false, not {value!r}")


def _strings(raw: dict[str, object], key: str, source: str) -> list[str]:
    value = raw[key]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    raise ConfigError(f"{source}: {key} must be a list of strings, not {value!r}")


def _load_pyproject_section() -> dict[str, object]:
    """Load [tool.heckler] from pyproject.toml."""
    pyproject = Path("pyproject.toml")
    if not pyproject.exists():
        return {}
    try:
        with open(pyproject, "rb") as f:
            data = tomllib.load(f)
    except (OSError, ValueError) as e:  # TOMLDecodeError is a ValueError
        raise ConfigError(f"pyproject.toml could not be read ({e})") from e
    tool = data.get("tool", {})
    if not isinstance(tool, dict):
        return {}
    result = tool.get("heckler", {})
    return result if isinstance(result, dict) else {}


# ---------------------------------------------------------------------------
# .heckler.yml
# ---------------------------------------------------------------------------
#
# The file is flat. A setting is a "key: value" line that starts in the
# first column, and a value is a word, a quoted string, a list in brackets
# on that line, or nothing followed by "- item" lines. "#" starts a comment.
#
# YAML has a great deal more than that. A reader that passed over what it
# did not know would take the settings under a nested key for top-level
# ones and split a quoted pattern at its comma, so the rest is refused, and
# the message names the line.

_YAML_KEY_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*)[ \t]*:(?:[ \t]+(.*))?")
_YAML_BOOLEANS = {"true": True, "yes": True, "on": True, "false": False, "no": False, "off": False}
_YAML_ITEM_RE = re.compile(
    r"""[ \t]*(?:
        (?P<double>"(?:[^"\\]|\\.)*")          # "double quoted", with escapes
      | (?P<single>'(?:[^']|'')*')             # 'single quoted', '' for a quote
      | (?P<plain>[^\s,\[\]{}"'][^,\[\]{}]*?)  # a plain word
    )[ \t]*(?:,|$)""",
    re.VERBOSE,
)
# What opens a YAML construct the flat format has no use for: an anchor, a
# tag, a block scalar, a mapping or a list inside a value, a directive.
# "*" opens an alias and is not here: most allowlist patterns start with
# one, and a file that cannot define an anchor has no alias for it to mean.
_YAML_NOT_PLAIN = tuple("&!|>{}[]%@`,")


def _load_yaml_file(path: Path) -> dict[str, object]:
    """Read a .heckler.yml."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as e:
        raise ConfigError(f"{path} could not be read ({e})") from e
    return _minimal_yaml_parse(text, str(path))


def _unreadable(where: str, line: str, why: str) -> ConfigError:
    return ConfigError(f"{where} could not be read ({why}): {spell_out(line.strip())}")


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


def _yaml_string(text: str, where: str, line: str) -> str:
    """One value as a string: quoted, or a plain word."""
    if text.startswith('"'):
        try:
            value = json.loads(text)
        except ValueError:
            value = None
        if not isinstance(value, str):
            raise _unreadable(where, line, "a double-quoted string has to close, with JSON escapes")
        return value
    if text.startswith("'"):
        closed = len(text) > 1 and text.endswith("'")
        if not closed or "'" in text[1:-1].replace("''", ""):
            raise _unreadable(where, line, "a single-quoted string has to close")
        return text[1:-1].replace("''", "'")
    if not text or text.startswith(_YAML_NOT_PLAIN) or ": " in text or text.endswith(":"):
        raise _unreadable(where, line, "a value is a word, a quoted string or a list of those")
    return text


def _yaml_inline_list(text: str, where: str, line: str) -> list[str]:
    """A list in brackets on one line: ``[a, "b, c", 'd']``."""
    if not text.endswith("]"):
        raise _unreadable(where, line, "a list in brackets has to close on the same line")
    body = text[1:-1]
    items: list[str] = []
    position = 0
    while body[position:].strip():
        m = _YAML_ITEM_RE.match(body, position)
        if not m or not m.lastgroup:
            raise _unreadable(where, line, "a list holds words or quoted strings, with commas")
        items.append(_yaml_string(m.group(m.lastgroup).strip(), where, line))
        position = m.end()
    return items


def _minimal_yaml_parse(text: str, source: str = ".heckler.yml") -> dict[str, object]:
    """Read a flat YAML settings file.

    Handles ``key: value``, ``key: [list]`` and ``- item`` lines under a key
    that has no value. Anything else raises ConfigError.
    """
    result: dict[str, object] = {}
    items: list[str] | None = None  # the list that "- item" lines add to

    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "---" and not result:
            continue  # the optional start of a document
        where = f"{source}, line {number}"

        # List item under a key
        if stripped == "-" or stripped.startswith(("- ", "-\t")):
            if items is None:
                raise _unreadable(where, line, "a list item has to follow a key that has no value")
            items.append(_yaml_string(_strip_inline_comment(stripped[1:].strip()), where, line))
            continue

        # Key: value pair
        m = _YAML_KEY_RE.fullmatch(line.rstrip())
        if not m:
            indented = line[:1] in (" ", "\t")
            why = "a setting starts in the first column" if indented else 'expected "key: value"'
            raise _unreadable(where, line, why)
        key, value = m.group(1), _strip_inline_comment((m.group(2) or "").strip())
        if key in result:
            raise _unreadable(where, line, f"{key} is set twice")

        items = None
        if not value:
            items = []
            result[key] = items
        elif value.startswith("["):
            result[key] = _yaml_inline_list(value, where, line)
        elif value.lower() in _YAML_BOOLEANS:
            result[key] = _YAML_BOOLEANS[value.lower()]
        else:
            result[key] = _yaml_string(value, where, line)

    return result
