"""Human-readable text formatter with optional ANSI colors."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..scanner import Finding

from ..characters import DANGEROUS_UNICODE_RE, Severity


def _escape_data(value: str) -> str:
    """*value* as the message of a workflow command, escaped as actions/toolkit escapes one."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(value: str) -> str:
    """*value* as a property of a workflow command, escaped as actions/toolkit escapes one."""
    return _escape_data(value).replace(":", "%3A").replace(",", "%2C")


def in_github_actions() -> bool:
    """Whether the GitHub Actions runner reads this output for workflow commands."""
    return os.environ.get("GITHUB_ACTIONS") == "true"


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


def not_a_command(line: str) -> str:
    """*line*, written so that the GitHub Actions runner does not read it as a command.

    The runner reads a line that starts with ``::``, once leading whitespace is
    trimmed, as a workflow command, and has an older form that starts with
    ``##[``. The first ``:`` of a leading ``::`` is written as ``<U+003A>``, and
    the first ``#`` of every ``##[`` as ``<U+0023>``. *line* has been through
    ``spell_out()``, so it holds no line break and no whitespace but spaces.
    """
    line = line.replace("##[", "<U+0023>#[")
    rest = line.lstrip()
    if rest.startswith("::"):
        line = line[: len(line) - len(rest)] + "<U+003A>" + rest[1:]
    return line


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
    in_gha = in_github_actions()
    lines: list[str] = []
    ours: set[int] = set()  # where in lines heckler's own ::error lines are

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
        summary_parts: list[str] = []
        for sev in Severity:
            if sev in counts:
                label = f"{counts[sev]} {sev.value.upper()}"
                if use_color:
                    label = f"{_SEVERITY_COLORS[sev]}{label}{_RESET}"
                summary_parts.append(label)
        lines.append(f"Found {len(findings)} dangerous character(s): {', '.join(summary_parts)}")
        lines.append("")

    for filepath, file_findings in by_file.items():
        if not quiet:
            header = spell_out(filepath)
            if in_gha:
                header = not_a_command(header)  # before the colour code goes in front
            if use_color:
                header = f"{_BOLD}{header}{_RESET}"
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
                line_str += f"  pkg:{spell_out(f.package)}"

            lines.append(line_str)

            if in_gha:
                safe_file = _escape_property(spell_out(f.file))
                message = _escape_data(f"{sev_label}: {f.codepoint_hex} ({f.char_name}){tag}")
                ours.add(len(lines))
                lines.append(f"::error file={safe_file},line={f.line},col={f.column}::{message}")

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

    if in_gha:
        lines = [ln if i in ours else not_a_command(ln) for i, ln in enumerate(lines)]
    return "\n".join(lines)


def _supports_color() -> bool:
    """Check if the terminal supports color output."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    import sys

    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
