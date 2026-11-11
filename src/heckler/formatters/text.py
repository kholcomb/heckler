"""Human-readable text formatter with optional ANSI colors."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..scanner import Finding

from ..characters import DANGEROUS_UNICODE_RE, Severity


def _sanitize_annotation_value(value: str) -> str:
    """Escape characters that have special meaning in GitHub Actions annotations."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(",", "%2C")


_SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[91m",  # Red
    Severity.HIGH: "\033[93m",  # Yellow
    Severity.MEDIUM: "\033[96m",  # Cyan
    Severity.LOW: "\033[37m",  # White
    Severity.INFO: "\033[90m",  # Gray
}
_RESET = "\033[0m"
_BOLD = "\033[1m"

# How much of a source line to show around a finding, in characters.
_EXCERPT_BEFORE = 40
_EXCERPT_AFTER = 40
_EXCERPT_MAX = 160


def _spell_out(ch: str) -> str:
    """Render one source character so that it can be seen and does nothing.

    Flagged characters and anything else unprintable become ``<U+XXXX>``.
    That covers control characters too, so a scanned file cannot send escape
    sequences to the terminal through heckler's output.
    """
    if ch == "\t":
        return " "
    if DANGEROUS_UNICODE_RE.match(ch) or not ch.isprintable():
        return f"<U+{ord(ch):04X}>"
    return ch


def spell_out(text: str) -> str:
    """*text* with every invisible or unprintable character written as ``<U+XXXX>``.

    For anything read from a scanned file that ends up in a message.
    """
    return "".join(_spell_out(ch) for ch in text)


def _excerpt(line: str, columns: list[int]) -> str:
    """The part of *line* around the findings at *columns* (1-based).

    A long line, such as a minified bundle, is cut to a window that starts
    shortly before the first finding.
    """
    line = line.rstrip("\r\n")
    first, last = min(columns) - 1, max(columns) - 1
    start = max(0, first - _EXCERPT_BEFORE)
    end = min(len(line), last + 1 + _EXCERPT_AFTER, start + _EXCERPT_MAX)
    body = "".join(_spell_out(ch) for ch in line[start:end])
    if start == 0:
        body = body.lstrip()
    return ("..." if start > 0 else "") + body + ("..." if end < len(line) else "")


def format_text(findings: list[Finding], *, color: bool = True, quiet: bool = False) -> str:
    """Format findings as human-readable text."""
    if not findings:
        if quiet:
            return ""
        return "No dangerous invisible Unicode characters found."

    use_color = color and _supports_color()
    lines: list[str] = []

    # Group by file
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)

    # Summary counts
    counts: dict[Severity, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    if not quiet:
        lines.append("")
        summary_parts = []
        for sev in Severity:
            if sev in counts:
                label = f"{counts[sev]} {sev.value.upper()}"
                if use_color:
                    label = f"{_SEVERITY_COLORS[sev]}{label}{_RESET}"
                summary_parts.append(label)
        lines.append(f"Found {len(findings)} dangerous character(s): {', '.join(summary_parts)}")
        lines.append("")

    # GitHub Actions annotations
    in_gha = os.environ.get("GITHUB_ACTIONS") == "true"

    for filepath, file_findings in by_file.items():
        if not quiet:
            header = filepath
            if use_color:
                header = f"{_BOLD}{filepath}{_RESET}"
            lines.append(header)

        columns_on_line: list[int] = []
        for i, f in enumerate(file_findings):
            sev_label = f.severity.value.upper()
            tag = ""
            if f.severity == Severity.INFO:
                pass  # part of a well-formed emoji, not an attack signature
            elif f.category.value == "variation_selector":
                tag = " [GLASSWORM]"
            elif f.category.value == "bidi_control":
                tag = " [TROJAN-SOURCE]"

            loc = f"  {f.line}:{f.column}"
            detail = f"{f.codepoint_hex} ({f.char_name}){tag}"

            if use_color:
                sev_color = _SEVERITY_COLORS.get(f.severity, "")
                line_str = f"{loc}  {sev_color}{sev_label}{_RESET}  {detail}"
            else:
                line_str = f"{loc}  {sev_label}  {detail}"

            if f.package:
                line_str += f"  pkg:{f.package}"

            lines.append(line_str)

            if in_gha:
                safe_file = _sanitize_annotation_value(f.file)
                safe_name = _sanitize_annotation_value(f.char_name)
                lines.append(
                    f"::error file={safe_file},line={f.line},col={f.column}"
                    f"::{sev_label}: {f.codepoint_hex} ({safe_name}){tag}"
                )

            # After the last finding on a source line, show that line once.
            columns_on_line.append(f.column)
            if i + 1 == len(file_findings) or file_findings[i + 1].line != f.line:
                if not quiet and f.line_content.strip():
                    lines.append(f"      {_excerpt(f.line_content, columns_on_line)}")
                columns_on_line = []

        if not quiet:
            lines.append("")

    if not quiet:
        n_files = len(by_file)
        lines.append(f"Total: {len(findings)} finding(s) across {n_files} file(s).")

    return "\n".join(lines)


def _supports_color() -> bool:
    """Check if the terminal supports color output."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    import sys

    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
