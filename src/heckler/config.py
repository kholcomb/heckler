"""Configuration loading for heckler.

Loads from: --config flag → .heckler.yml → [tool.heckler] in pyproject.toml → defaults.
Zero external dependencies — includes a minimal YAML parser for the flat config format.
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from .characters import Severity
from .scanner import DEFAULT_SKIP_DIRS, DEFAULT_TEXT_EXTENSIONS


@dataclass
class Config:
    skip_dirs: frozenset[str] = field(default_factory=lambda: DEFAULT_SKIP_DIRS)
    text_extensions: frozenset[str] = field(default_factory=lambda: DEFAULT_TEXT_EXTENSIONS)
    severity_threshold: Severity = Severity.LOW
    exclude_patterns: list[str] = field(default_factory=list)
    allow_bom: bool = True
    scan_deps: bool = False

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
        # Explicit path that doesn't exist is silently ignored
    else:
        # Auto-discover
        for candidate in ('.heckler.yml', '.heckler.yaml'):
            p = Path(candidate)
            if p.exists():
                raw = _load_yaml_file(p)
                break
        else:
            # Try pyproject.toml
            raw = _load_pyproject_section()

    config = Config.defaults()

    if 'severity' in raw:
        sev_str = str(raw['severity']).upper()
        with contextlib.suppress(KeyError):
            config.severity_threshold = Severity[sev_str]

    if 'allowlist' in raw and isinstance(raw['allowlist'], list):
        config.exclude_patterns = [str(p) for p in raw['allowlist']]

    if 'allow_bom' in raw:
        config.allow_bom = bool(raw['allow_bom'])

    if 'extra_skip_dirs' in raw and isinstance(raw['extra_skip_dirs'], list):
        config.skip_dirs = config.skip_dirs | frozenset(str(d) for d in raw['extra_skip_dirs'])

    if 'extra_extensions' in raw and isinstance(raw['extra_extensions'], list):
        config.text_extensions = config.text_extensions | frozenset(
            str(e) if e.startswith('.') else f'.{e}' for e in raw['extra_extensions']
        )

    config.scan_deps = scan_deps

    return config


def _load_yaml_file(path: Path) -> dict[str, object]:
    """Load a YAML file. Tries PyYAML first, falls back to minimal parser."""
    text = path.read_text(encoding='utf-8')
    try:
        import yaml  # type: ignore[import-untyped]
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}
    except ImportError:
        return _minimal_yaml_parse(text)


def _load_pyproject_section() -> dict[str, object]:
    """Load [tool.heckler] from pyproject.toml."""
    pyproject = Path('pyproject.toml')
    if not pyproject.exists():
        return {}
    try:
        # Python 3.11+
        import tomllib  # type: ignore[import-not-found]
        with open(pyproject, 'rb') as f:
            data = tomllib.load(f)
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[import-not-found]
            with open(pyproject, 'rb') as f:
                data = tomllib.load(f)
        except ImportError:
            return {}
    tool: dict[str, object] = data.get('tool', {})
    if not isinstance(tool, dict):
        return {}
    result = tool.get('heckler', {})
    return result if isinstance(result, dict) else {}


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
        if not stripped or stripped.startswith('#'):
            continue

        # List item under a key
        if stripped.startswith('- ') and current_key is not None:
            if current_list is None:
                current_list = []
            val = stripped[2:].strip().strip('"').strip("'")
            current_list.append(val)
            result[current_key] = current_list
            continue

        # Key: value pair
        m = re.match(r'^(\w[\w_-]*)\s*:\s*(.*)', stripped)
        if m:
            # Save previous list
            key = m.group(1)
            val_str = m.group(2).strip()

            current_key = key
            current_list = None

            if not val_str:
                # Could be a list or nested dict following
                result[key] = []
                current_list = []
            elif val_str == '[]':
                result[key] = []
                current_list = []
            elif val_str.lower() in ('true', 'yes'):
                result[key] = True
            elif val_str.lower() in ('false', 'no'):
                result[key] = False
            elif val_str.startswith('[') and val_str.endswith(']'):
                # Inline list
                items = [
                    i.strip().strip('"').strip("'")
                    for i in val_str[1:-1].split(',')
                    if i.strip()
                ]
                result[key] = items
            else:
                result[key] = val_str.strip('"').strip("'")
        else:
            current_key = None
            current_list = None

    return result
