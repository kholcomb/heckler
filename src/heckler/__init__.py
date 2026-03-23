"""heckler: Detect dangerous invisible Unicode characters."""

from __future__ import annotations

from ._version import __version__
from .characters import Severity, ThreatCategory
from .config import Config, load_config
from .scanner import Finding, Scanner

__all__ = [
    "__version__",
    "Config",
    "Finding",
    "Scanner",
    "Severity",
    "ThreatCategory",
    "load_config",
    "scan",
]


def scan(
    path: str = ".",
    *,
    scan_deps: bool = False,
    config_path: str | None = None,
) -> list[Finding]:
    """Convenience function: scan a path and return findings."""
    from pathlib import Path as P

    config = load_config(config_path=config_path, scan_deps=scan_deps)
    scanner = Scanner(
        skip_dirs=config.skip_dirs,
        text_extensions=config.text_extensions,
        severity_threshold=config.severity_threshold,
        exclude_patterns=config.exclude_patterns,
        allow_bom=config.allow_bom,
        scan_deps=config.scan_deps,
    )
    return scanner.scan_path(P(path))
