"""Command-line interface for heckler."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import NoReturn

from ._output import write_err, write_out
from ._version import __version__
from .characters import Severity
from .config import Config, ConfigError, load_config
from .formatters import get_formatter
from .formatters.text import spell_out
from .scanner import Finding, Scanner

# How many skipped directories or files a note names before it counts the rest.
_MAX_PATHS_NAMED = 5


class _Parser(argparse.ArgumentParser):
    """An argument parser whose errors go out through ``write_err()``.

    argparse echoes back an argument it cannot use, so the text of an
    error is input like any other. The usage and the message read as
    argparse writes them.
    """

    def error(self, message: str) -> NoReturn:
        # Python 3.14 colours the usage on a terminal, and write_err() would
        # spell every escape of it out. The parser exits below, so help and
        # version output are not affected; before 3.14 this is unused.
        self.color = False
        for line in self.format_usage().splitlines():
            write_err(line)
        write_err(f"{self.prog}: error: {message}")
        self.exit(2)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="heckler",
        description=(
            "Detect dangerous invisible Unicode characters in source code and dependencies."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    parser.add_argument(
        "paths",
        nargs="*",
        default=None,
        help="Files or directories to scan (default: current directory)",
    )
    parser.add_argument(
        "--vet",
        metavar="PACKAGE",
        help=(
            "Download and scan a package before installing (e.g., express@4.18.0, requests==2.31.0)"
        ),
    )

    parser.add_argument(
        "--registry",
        choices=["npm", "pypi"],
        help="Package registry for --vet (auto-detected if omitted)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help=(
            "Exit with code 1 if findings detected, and with code 2 if something"
            " could not be scanned"
        ),
    )
    parser.add_argument(
        "--severity",
        choices=[s.value for s in Severity],
        default=None,
        help="Minimum severity to report (default: low)",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="Path to .heckler.yml config file",
    )
    parser.add_argument(
        "--scan-deps",
        action="store_true",
        help="Include dependency directories (node_modules, vendor, site-packages, etc.)",
    )
    parser.add_argument(
        "--diff-only",
        action="store_true",
        help="With --scan-deps, only scan packages changed in staged lockfile diffs",
    )
    parser.add_argument(
        "--allow-unscanned",
        action="store_true",
        help=(
            "Do not fail (exit code 2) over what could not be scanned: with --ci,"
            " a file that is unreadable or too large; with --diff-only, also a"
            " changed package that is not installed or is installed at a different"
            " version, and a lockfile heckler cannot read; with --vet, a file of"
            " the package that could not be unpacked or read"
        ),
    )
    parser.add_argument(
        "--no-suppress",
        action="store_true",
        help="Ignore heckler-ignore comments and report what they hide",
    )
    parser.add_argument(
        "--all-text",
        action="store_true",
        help=(
            "Scan every text file inside dependency directories too, where a scan"
            " otherwise keeps to code"
        ),
    )
    parser.add_argument(
        "--skip-binary",
        action="store_true",
        help=(
            "Leave out a file passed by name when its content is not text, as a directory walk does"
        ),
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Only output findings, no summary",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Load config
    try:
        config = load_config(
            config_path=args.config,
            scan_deps=args.scan_deps,
        )
    except (FileNotFoundError, ConfigError) as e:
        # Settings that were not read are not settings to run with: a scan
        # under the defaults could report less than the file asked for.
        write_err(f"Error: {e}")
        return 2

    # CLI overrides
    if args.severity:
        config.severity_threshold = Severity(args.severity)

    # Handle --vet mode
    if args.vet:
        if args.paths:
            parser.error("argument paths: not allowed with argument --vet")
        return _run_vet(args, config)

    # Handle --diff-only mode
    if args.diff_only:
        return _run_diff_only(args, config)

    # Standard scan mode
    paths = [Path(p) for p in (args.paths or ["."])]
    missing = [p for p in paths if not p.exists()]
    if missing:
        # Scanning nothing and reporting it as clean is the one thing a
        # mistyped path must not do.
        write_err(f"Error: path not found: {', '.join(map(str, missing))}")
        return 2

    scanner = _build_scanner(args, config, scan_deps=config.scan_deps)
    findings = scanner.scan_paths(paths)
    unscanned = _report_skipped(scanner)
    return _finish(args, scanner, findings, unscanned, "Pass --allow-unscanned to accept this.")


def _build_scanner(args: argparse.Namespace, config: Config, *, scan_deps: bool) -> Scanner:
    return Scanner(
        skip_dirs=config.skip_dirs,
        text_extensions=config.text_extensions,
        all_text=args.all_text,
        skip_binary=args.skip_binary,
        severity_threshold=config.severity_threshold,
        exclude_patterns=config.exclude_patterns,
        allow_bom=config.allow_bom,
        allow_emoji=config.allow_emoji,
        scan_deps=scan_deps,
        honor_directives=not args.no_suppress,
    )


def _report_skipped(scanner: Scanner) -> list[str]:
    """Warn about each file the scanner could not read, and return the warnings."""
    # A name is written by whoever made the file. Spelled out, it cannot send
    # an escape sequence or a line break to the terminal.
    messages = [f"{spell_out(path)} was not scanned: {reason}" for path, reason in scanner.skipped]
    for message in messages:
        write_err(f"Warning: {message}")
    return messages


def _finish(
    args: argparse.Namespace,
    scanner: Scanner,
    findings: list[Finding],
    unscanned: list[str],
    advice: str,
) -> int:
    """Print the report and the notes that go with it, and pick the exit code.

    *unscanned* describes what was meant to be scanned and was not; *advice*
    is what to do about it.
    """
    formatter = get_formatter(args.format)
    color = not args.no_color and args.format == "text"
    output = formatter(findings, color=color, quiet=args.quiet)
    # "Nothing found" would be the wrong thing to say about files or packages
    # that were never looked at; the warnings already tell that story.
    nothing_was_checked = args.format == "text" and unscanned and not findings
    if output and not nothing_was_checked:
        write_out(output, json_document=args.format != "text")

    if not args.quiet:
        _report_suppressions(scanner)

    if args.ci and findings:
        return 1
    if args.ci and unscanned and not args.allow_unscanned:
        # Something nobody looked at is not a clean result.
        write_err(
            f"Error: {len(unscanned)} item(s) could not be scanned (see the warnings"
            f" above). {advice}",
        )
        return 2
    return 0


def _name_some(paths: list[str]) -> str:
    """The first few of *paths*, and how many more there are.

    Each name is spelled out: a file left out as binary is named by whoever
    made it, and an escape sequence or a line break in the name would hide
    the note or add a line to it.
    """
    named = ", ".join(spell_out(path) for path in paths[:_MAX_PATHS_NAMED])
    more = len(paths) - _MAX_PATHS_NAMED
    return f"{named} and {more} more" if more > 0 else named


def _report_suppressions(scanner: Scanner) -> None:
    """Say what the scan left out or held back, so that it is never nothing."""
    if scanner.skipped_dirs:
        named = _name_some(scanner.skipped_dirs)
        advice = "" if scanner.scan_deps else " --scan-deps scans dependency directories."
        write_err(f"Note: not scanned, skipped by directory name: {named}.{advice}")
    if scanner.binary:
        # By name, so that a file made to be one of these can be told from
        # the images and archives that are expected. "As text", because one
        # that is mostly text was scanned for the text inside it, and may
        # have findings in the report above.
        named = _name_some(scanner.binary)
        write_err(f"Note: not scanned as text, binary by content: {named}.")
    if scanner.suppressed:
        write_err(
            f"Note: {sum(scanner.suppressed.values())} finding(s) suppressed in"
            f" {len(scanner.suppressed)} file(s) by heckler-ignore comments."
            " Run with --no-suppress to list them.",
        )
    if scanner.unlisted:
        write_err(
            f"Note: {scanner.unlisted} of the findings are on a line with a heckler-ignore"
            " comment that does not cover them. Without a list, a comment covers MEDIUM"
            " and below; name the code points to cover more, for example:"
            " heckler-ignore U+FE0F",
        )


def _run_vet(args: argparse.Namespace, config: Config) -> int:
    """Run package vetting mode."""
    from .vet import vet_package

    return vet_package(
        spec=args.vet,
        registry_override=args.registry,
        config=config,
        output_format=args.format,
        color=not args.no_color,
        quiet=args.quiet,
        allow_unscanned=args.allow_unscanned,
    )


def _run_diff_only(args: argparse.Namespace, config: Config) -> int:
    """Run lockfile diff-based dependency scanning."""
    from .lockfile import scan_changed_deps

    scanner = _build_scanner(args, config, scan_deps=True)

    lockfile_paths: list[str] = args.paths or []
    if not lockfile_paths:
        # No lockfile is no packages, and no packages would come out as clean.
        write_err(
            "Error: --diff-only needs the lockfiles to check, for example:"
            " heckler --scan-deps --diff-only package-lock.json",
        )
        return 2
    unscanned: list[str] = []
    findings = scan_changed_deps(lockfile_paths, scanner, unscanned)
    unscanned += _report_skipped(scanner)
    advice = (
        "Install the dependencies the lockfile describes and run again, or pass"
        " --allow-unscanned to accept this."
    )
    return _finish(args, scanner, findings, unscanned, advice)


def cli_main() -> None:
    """Entry point for console_scripts."""
    sys.exit(main())
