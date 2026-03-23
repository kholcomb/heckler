"""Output formatters for heckler findings."""

from __future__ import annotations

from collections.abc import Callable

from .json_fmt import format_json
from .sarif import format_sarif
from .text import format_text

__all__ = ["format_text", "format_json", "format_sarif", "get_formatter"]


def get_formatter(name: str) -> Callable[..., str]:
    """Get a formatter function by name."""
    formatters: dict[str, Callable[..., str]] = {
        "text": format_text,
        "json": format_json,
        "sarif": format_sarif,
    }
    if name not in formatters:
        raise ValueError(f"Unknown output format: {name!r}. Choose from: {', '.join(formatters)}")
    return formatters[name]
