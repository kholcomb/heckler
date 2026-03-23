"""Package vetting: download and scan a package before installing it."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

from .config import Config
from .formatters import get_formatter
from .scanner import Scanner


def detect_registry(spec: str) -> str:
    """Infer package registry from spec syntax.

    Returns 'npm', 'pypi', or 'unknown'.
    """
    if '==' in spec or '>=' in spec or '<=' in spec or '~=' in spec:
        return 'pypi'
    # Scoped npm: @scope/name or @scope/name@version
    if spec.startswith('@'):
        return 'npm'
    # Unscoped npm with version: name@version
    if '@' in spec:
        return 'npm'
    return 'unknown'


def check_tool_available(registry: str) -> None:
    """Verify that the required package manager CLI is installed."""
    if registry == 'npm':
        if shutil.which('npm') is None:
            print("Error: npm not found. Install Node.js to vet npm packages.", file=sys.stderr)
            sys.exit(2)
    elif registry == 'pypi' and shutil.which('pip3') is None and shutil.which('pip') is None:
            print("Error: pip not found. Install Python pip to vet PyPI packages.", file=sys.stderr)
            sys.exit(2)


def download_package(spec: str, registry: str, tmpdir: str) -> Path:
    """Download a package archive to tmpdir. Returns path to the archive."""
    if registry == 'npm':
        result = subprocess.run(
            ['npm', 'pack', spec, '--pack-destination', tmpdir, '--ignore-scripts'],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            print(f"Error: Package \"{spec}\" not found in npm.\n{result.stderr}", file=sys.stderr)
            sys.exit(2)
        tgz_name = result.stdout.strip().split('\n')[-1]
        return Path(tmpdir) / tgz_name

    else:  # pypi
        pip_cmd = 'pip3' if shutil.which('pip3') else 'pip'
        # Try source distribution first
        result = subprocess.run(
            [pip_cmd, 'download', '--no-deps', '--no-binary', ':all:', '-d', tmpdir, spec],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            # Fall back to wheel
            result = subprocess.run(
                [pip_cmd, 'download', '--no-deps', '-d', tmpdir, spec],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode != 0:
                print(
                    f"Error: Package \"{spec}\" not found in PyPI.\n{result.stderr}",
                    file=sys.stderr,
                )
                sys.exit(2)

        # Find the downloaded file
        files = list(Path(tmpdir).iterdir())
        if not files:
            print(f"Error: Failed to download \"{spec}\".", file=sys.stderr)
            sys.exit(2)
        return files[0]


def extract_package(archive_path: Path, tmpdir: str) -> Path:
    """Extract a package archive safely. Guards against path traversal,
    symlink attacks, and zip bombs."""
    extract_dir = Path(tmpdir) / 'extracted'
    extract_dir.mkdir(exist_ok=True)
    resolved_root = extract_dir.resolve()

    name = archive_path.name.lower()
    try:
        if name.endswith(('.tgz', '.tar.gz', '.tar.bz2')) or (
            not name.endswith(('.whl', '.zip'))
        ):
            _safe_tar_extract(archive_path, extract_dir, resolved_root)
        else:
            _safe_zip_extract(archive_path, extract_dir, resolved_root)
    except (tarfile.TarError, zipfile.BadZipFile, _UnsafeArchiveError) as e:
        print(f"Error: Failed to extract package archive: {e}", file=sys.stderr)
        sys.exit(2)

    return extract_dir


class _UnsafeArchiveError(Exception):
    """Raised when an archive contains path traversal or symlink attacks."""


# 50 MB uncompressed limit per file to guard against zip bombs
_MAX_EXTRACT_SIZE = 50 * 1024 * 1024
# 500 MB total extraction limit
_MAX_TOTAL_SIZE = 500 * 1024 * 1024


def _safe_tar_extract(archive_path: Path, extract_dir: Path, resolved_root: Path) -> None:
    """Extract a tar archive with path traversal and symlink protection."""
    with tarfile.open(archive_path) as tf:
        # Python 3.12+ has filter='data' which handles this natively.
        # For 3.9-3.11, we validate manually.
        try:
            tf.extractall(extract_dir, filter='data')
            return
        except TypeError:
            # filter parameter not supported (Python < 3.12)
            pass
        except tarfile.TarError as e:
            # Python 3.12+ filter='data' raises FilterError subclasses for
            # path traversal, symlinks, etc. Wrap as our error type.
            raise _UnsafeArchiveError(f"Unsafe archive: {e}") from e

        # Manual safe extraction for Python 3.9-3.11
        total_size = 0
        for member in tf.getmembers():
            _validate_archive_member(member.name, resolved_root, extract_dir)

            if member.issym() or member.islnk():
                raise _UnsafeArchiveError(
                    f"Archive contains symlink/hardlink: {member.name}"
                )
            if member.isdev():
                raise _UnsafeArchiveError(
                    f"Archive contains device file: {member.name}"
                )
            if member.size > _MAX_EXTRACT_SIZE:
                raise _UnsafeArchiveError(
                    f"File too large ({member.size} bytes): {member.name}"
                )
            total_size += member.size
            if total_size > _MAX_TOTAL_SIZE:
                raise _UnsafeArchiveError(
                    f"Total extraction size exceeds {_MAX_TOTAL_SIZE} bytes"
                )

        # Safe to extract — rewind and extract only regular files/dirs
        tf.extractall(extract_dir, members=[
            m for m in tf.getmembers()
            if m.isfile() or m.isdir()
        ])


def _safe_zip_extract(archive_path: Path, extract_dir: Path, resolved_root: Path) -> None:
    """Extract a zip archive with path traversal protection."""
    with zipfile.ZipFile(archive_path, 'r') as zf:
        total_size = 0
        for info in zf.infolist():
            _validate_archive_member(info.filename, resolved_root, extract_dir)

            if info.file_size > _MAX_EXTRACT_SIZE:
                raise _UnsafeArchiveError(
                    f"File too large ({info.file_size} bytes): {info.filename}"
                )
            total_size += info.file_size
            if total_size > _MAX_TOTAL_SIZE:
                raise _UnsafeArchiveError(
                    f"Total extraction size exceeds {_MAX_TOTAL_SIZE} bytes"
                )

            # Check for symlinks in zip (external_attr encodes Unix mode)
            unix_mode = info.external_attr >> 16
            if unix_mode and (unix_mode & 0o120000) == 0o120000:
                raise _UnsafeArchiveError(
                    f"Archive contains symlink: {info.filename}"
                )

        # All entries validated — extract
        zf.extractall(extract_dir)


def _validate_archive_member(member_name: str, resolved_root: Path, extract_dir: Path) -> None:
    """Reject archive members that would escape the extraction directory."""
    # Normalize and check for path traversal
    if '..' in member_name.split('/') or '..' in member_name.split('\\'):
        raise _UnsafeArchiveError(
            f"Path traversal detected: {member_name}"
        )
    # Resolve the target path and verify it's under the extraction root
    target = (extract_dir / member_name).resolve()
    if not str(target).startswith(str(resolved_root)):
        raise _UnsafeArchiveError(
            f"Path escapes extraction directory: {member_name}"
        )


def vet_package(
    spec: str,
    registry_override: str | None,
    config: Config,
    output_format: str = "text",
    color: bool = True,
    quiet: bool = False,
) -> int:
    """Download, scan, and report on a package. Returns exit code."""
    registry = registry_override or detect_registry(spec)
    if registry == 'unknown':
        print(
            f"Error: Cannot determine registry for \"{spec}\". "
            f"Use --registry npm or --registry pypi.",
            file=sys.stderr,
        )
        return 2

    check_tool_available(registry)

    with tempfile.TemporaryDirectory(prefix='glassworm-vet-') as tmpdir:
        archive = download_package(spec, registry, tmpdir)
        extract_dir = extract_package(archive, tmpdir)

        scanner = Scanner(
            skip_dirs=frozenset(),  # Don't skip anything in extracted package
            text_extensions=config.text_extensions,
            severity_threshold=config.severity_threshold,
            exclude_patterns=config.exclude_patterns,
            allow_bom=config.allow_bom,
            scan_deps=True,
        )
        findings = scanner.scan_path(extract_dir)

        # Rewrite file paths to be relative to package root
        for f in findings:
            rel = f.file.replace(str(extract_dir), '').lstrip('/')
            f.file = rel
            f.source = "dependency"
            f.package = spec

    formatter = get_formatter(output_format)
    output = formatter(findings, color=color, quiet=quiet)

    # Prepend vet summary header
    if output_format == "text":
        if findings:
            counts: dict[str, int] = {}
            for f in findings:
                sev = f.severity.value.upper()
                counts[sev] = counts.get(sev, 0) + 1
            count_str = ', '.join(f"{v} {k}" for k, v in counts.items())
            header = (
                f"[VET] {spec} ({registry}) — {len(findings)} finding(s)"
                f" ({count_str}). DO NOT INSTALL."
            )
        else:
            header = f"[VET] {spec} ({registry}) — 0 findings. CLEAN."
        print(header)

    if output:
        print(output)

    return 1 if findings else 0
