"""Command-line interface for heckler."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ._version import __version__
from .characters import Severity
from .config import Config, load_config
from .formatters import get_formatter
from .scanner import Scanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="heckler",
        description=(
            "Detect dangerous invisible Unicode characters"
            " in source code and dependencies."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    # Mutually exclusive: scan paths vs vet a package
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "paths",
        nargs="*",
        default=None,
        help="Files or directories to scan (default: current directory)",
    )
    group.add_argument(
        "--vet",
        metavar="PACKAGE",
        help=(
            "Download and scan a package before installing"
            " (e.g., express@4.18.0, requests==2.31.0)"
        ),
    )

    parser.add_argument(
        "--registry",
        choices=["npm", "pypi"],
        help="Package registry for --vet (auto-detected if omitted)",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="Exit with code 1 if findings detected",
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
        "--all-text",
        action="store_true",
        help="Scan all text files regardless of extension",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Only output findings, no summary",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Load config
    config = load_config(
        config_path=args.config,
        scan_deps=args.scan_deps,
    )

    # CLI overrides
    if args.severity:
        config.severity_threshold = Severity(args.severity)

    # Handle --vet mode
    if args.vet:
        return _run_vet(args, config)

    # Handle --diff-only mode
    if args.diff_only:
        return _run_diff_only(args, config)

    # Standard scan mode
    scanner = Scanner(
        skip_dirs=config.skip_dirs,
        text_extensions=config.text_extensions,
        severity_threshold=config.severity_threshold,
        exclude_patterns=config.exclude_patterns,
        allow_bom=config.allow_bom,
        scan_deps=config.scan_deps,
    )

    paths = [Path(p) for p in (args.paths or ["."])]
    findings = scanner.scan_paths(paths)

    # Format and output
    formatter = get_formatter(args.format)
    color = not args.no_color and args.format == "text"
    output = formatter(findings, color=color, quiet=args.quiet)
    if output:
        print(output)

    if args.ci and findings:
        return 1
    return 0


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
    )


def _run_diff_only(args: argparse.Namespace, config: Config) -> int:
    """Run lockfile diff-based dependency scanning."""
    from .lockfile import scan_changed_deps
    from .scanner import Scanner

    scanner = Scanner(
        skip_dirs=config.skip_dirs,
        text_extensions=config.text_extensions,
        severity_threshold=config.severity_threshold,
        exclude_patterns=config.exclude_patterns,
        allow_bom=config.allow_bom,
        scan_deps=True,
    )

    lockfile_paths = args.paths or []
    findings = scan_changed_deps(lockfile_paths, scanner)

    formatter = get_formatter(args.format)
    color = not args.no_color and args.format == "text"
    output = formatter(findings, color=color, quiet=args.quiet)
    if output:
        print(output)

    if args.ci and findings:
        return 1
    return 0


def cli_main() -> None:
    """Entry point for console_scripts."""
    sys.exit(main())
