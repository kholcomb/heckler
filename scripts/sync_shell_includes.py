#!/usr/bin/env python3
"""Write the file list of heckler-scan.sh from the Python scanner's lists.

The shell fallback has to work where there is no Python, so it carries its
own copy of the names the scanner looks at by default. This script writes
that copy, between the two marker lines in heckler-scan.sh:

    python scripts/sync_shell_includes.py           # rewrite the list
    python scripts/sync_shell_includes.py --check   # exit 1 if it is out of date

Run it after changing DEFAULT_TEXT_EXTENSIONS, KNOWN_FILENAMES or
KNOWN_FILENAME_PREFIXES in src/heckler/scanner.py. tests/test_coverage.py
makes the same comparison, so the two cannot drift apart unnoticed.
"""

from __future__ import annotations

import sys
from pathlib import Path

from heckler.scanner import DEFAULT_TEXT_EXTENSIONS, KNOWN_FILENAME_PREFIXES, KNOWN_FILENAMES

SCRIPT = Path(__file__).with_name("heckler-scan.sh")
BEGIN = "# BEGIN GENERATED INCLUDES: written by scripts/sync_shell_includes.py, do not edit"
END = "# END GENERATED INCLUDES"
_WIDTH = 78


def include_globs() -> list[str]:
    """The file-name globs that select what the Python scanner selects by default."""
    globs = [f"*{extension}" for extension in sorted(DEFAULT_TEXT_EXTENSIONS)]
    globs += sorted(KNOWN_FILENAMES)
    globs += [f"{prefix}*" for prefix in sorted(KNOWN_FILENAME_PREFIXES)]
    return globs


def render() -> str:
    """The generated block, marker lines included."""
    lines = [BEGIN, "INCLUDES=("]
    row = " "
    for glob in include_globs():
        if "'" in glob:
            raise ValueError(f"cannot quote {glob!r} for the shell")
        item = f" --include='{glob}'"
        if len(row) + len(item) > _WIDTH and row.strip():
            lines.append(row)
            row = " "
        row += item
    lines += [row, ")", END]
    return "\n".join(lines)


def replace_block(script_text: str) -> str:
    """*script_text* with the block between the markers regenerated."""
    start = script_text.index(BEGIN)
    end = script_text.index(END, start) + len(END)
    return script_text[:start] + render() + script_text[end:]


def main(argv: list[str]) -> int:
    current = SCRIPT.read_text(encoding="utf-8")
    updated = replace_block(current)
    if "--check" in argv:
        if current != updated:
            print(
                f"{SCRIPT.name} does not match the scanner's lists."
                " Run: python scripts/sync_shell_includes.py",
                file=sys.stderr,
            )
            return 1
        return 0
    if current != updated:
        SCRIPT.write_text(updated, encoding="utf-8")
        print(f"Updated {SCRIPT.name}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
