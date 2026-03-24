"""Package vetting: download and scan a package before installing it.

Downloads packages directly from public registry APIs (registry.npmjs.org,
pypi.org) using only stdlib urllib — no npm/pip subprocess required.  This
eliminates the risk of executing package build scripts (setup.py) during
download and removes the trust dependency on locally-installed package
managers.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from .config import Config
from .formatters import get_formatter
from .scanner import Scanner

_NPM_REGISTRY = "https://registry.npmjs.org"
_PYPI_REGISTRY = "https://pypi.org"

_PRIVATE_REGISTRY_WARNING = (
    "Note: --vet fetches packages directly from public registries "
    "(registry.npmjs.org, pypi.org). Private or corporate registries "
    "are not supported."
)


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


def _parse_spec(spec: str, registry: str) -> tuple[str, str | None]:
    """Parse a package spec into (name, version | None).

    For PyPI, only exact-match ``==`` versions are supported; range
    specifiers (``>=``, ``~=``, etc.) cause a hard exit because the
    registry JSON API has no solver.
    """
    if registry == 'npm':
        if spec.startswith('@'):
            # Scoped: @scope/name@version — split on the *last* @
            rest = spec[1:]
            if '@' in rest:
                idx = rest.rindex('@')
                return '@' + rest[:idx], rest[idx + 1:] or None
            return spec, None
        if '@' in spec:
            idx = spec.index('@')
            return spec[:idx], spec[idx + 1:] or None
        return spec, None

    # PyPI
    for op in ('>=', '<=', '~=', '!='):
        if op in spec:
            base = spec.split(op)[0].strip()
            print(
                f'Error: --vet requires an exact version (e.g., {base}==X.Y.Z). '
                f'Version ranges are not supported with direct registry fetching.',
                file=sys.stderr,
            )
            sys.exit(2)
    if '==' in spec:
        name, version = spec.split('==', 1)
        return name.strip(), version.strip()
    return spec.strip(), None


def _fetch_json(url: str) -> dict[str, object]:
    """Fetch and parse JSON from *url*. Returns ``{}`` on 404."""
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            data: dict[str, object] = json.loads(resp.read())
            return data
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {}
        raise


def _download_file(url: str, dest: Path) -> None:
    """Stream a URL to a local file."""
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
        dest.write_bytes(resp.read())


def _verify_checksum(path: Path, algorithm: str, expected: str, label: str) -> None:
    """Verify a downloaded file's checksum. Exits on mismatch."""
    h = hashlib.new(algorithm)
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    actual = h.hexdigest()
    if actual != expected:
        print(
            f"Error: Checksum mismatch for {label}\n"
            f"  Expected ({algorithm}): {expected}\n"
            f"  Got:                    {actual}",
            file=sys.stderr,
        )
        sys.exit(2)


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

def _download_npm(name: str, version: str | None, tmpdir: str) -> Path:
    """Fetch an npm tarball directly from the public registry."""
    encoded = urllib.parse.quote(name, safe='@')
    tag = version if version else 'latest'
    url = f"{_NPM_REGISTRY}/{encoded}/{tag}"

    try:
        meta = _fetch_json(url)
    except (urllib.error.URLError, OSError) as e:
        print(f"Error: Failed to fetch npm registry metadata: {e}", file=sys.stderr)
        sys.exit(2)

    if not meta:
        label = f"{name}@{version}" if version else name
        print(f'Error: Package "{label}" not found in npm registry.', file=sys.stderr)
        sys.exit(2)

    dist = meta.get("dist")
    tarball_url = dist.get("tarball") if isinstance(dist, dict) else None
    if not tarball_url or not isinstance(tarball_url, str):
        print(f'Error: No tarball URL found for "{name}".', file=sys.stderr)
        sys.exit(2)

    # Extract expected checksum from registry metadata
    expected_shasum = dist.get("shasum") if isinstance(dist, dict) else None

    filename: str = tarball_url.rsplit('/', 1)[-1]
    dest: Path = Path(tmpdir) / filename

    try:
        _download_file(tarball_url, dest)
    except (urllib.error.URLError, OSError) as e:
        print(f"Error: Failed to download npm package: {e}", file=sys.stderr)
        sys.exit(2)

    if isinstance(expected_shasum, str):
        _verify_checksum(dest, "sha1", expected_shasum, f"{name} (npm)")

    return dest


# ---------------------------------------------------------------------------
# PyPI
# ---------------------------------------------------------------------------

def _download_pypi(name: str, version: str | None, tmpdir: str) -> Path:
    """Fetch a PyPI package directly from the public registry.

    Prefers wheels (no code execution) over sdists.
    """
    encoded = urllib.parse.quote(name, safe='')
    if version:
        url = f"{_PYPI_REGISTRY}/pypi/{encoded}/{version}/json"
    else:
        url = f"{_PYPI_REGISTRY}/pypi/{encoded}/json"

    try:
        meta = _fetch_json(url)
    except (urllib.error.URLError, OSError) as e:
        print(f"Error: Failed to fetch PyPI metadata: {e}", file=sys.stderr)
        sys.exit(2)

    if not meta:
        label = f"{name}=={version}" if version else name
        print(f'Error: Package "{label}" not found on PyPI.', file=sys.stderr)
        sys.exit(2)

    urls = meta.get("urls")
    if not isinstance(urls, list) or not urls:
        print(f'Error: No downloads available for "{name}".', file=sys.stderr)
        sys.exit(2)

    def _is_type(u: object, t: str) -> bool:
        return isinstance(u, dict) and u.get("packagetype") == t

    wheel = next((u for u in urls if _is_type(u, "bdist_wheel")), None)
    sdist = next((u for u in urls if _is_type(u, "sdist")), None)
    chosen = wheel or sdist
    if not isinstance(chosen, dict):
        print(f'Error: No suitable download found for "{name}".', file=sys.stderr)
        sys.exit(2)

    download_url = chosen.get("url")
    filename = chosen.get("filename")
    if not isinstance(download_url, str) or not isinstance(filename, str):
        print(f'Error: Malformed download metadata for "{name}".', file=sys.stderr)
        sys.exit(2)

    # Extract expected SHA-256 from registry metadata
    digests = chosen.get("digests")
    expected_sha256 = digests.get("sha256") if isinstance(digests, dict) else None

    dest = Path(tmpdir) / filename
    try:
        _download_file(download_url, dest)
    except (urllib.error.URLError, OSError) as e:
        print(f"Error: Failed to download PyPI package: {e}", file=sys.stderr)
        sys.exit(2)

    if isinstance(expected_sha256, str):
        _verify_checksum(dest, "sha256", expected_sha256, f"{name} (pypi)")

    return dest


# ---------------------------------------------------------------------------
# Public download entry point
# ---------------------------------------------------------------------------

def download_package(spec: str, registry: str, tmpdir: str) -> Path:
    """Download a package archive to *tmpdir* via registry API.

    Returns the path to the downloaded archive file.
    """
    name, version = _parse_spec(spec, registry)

    if registry == 'npm':
        return _download_npm(name, version, tmpdir)
    return _download_pypi(name, version, tmpdir)


# ---------------------------------------------------------------------------
# Archive extraction (unchanged)
# ---------------------------------------------------------------------------

def extract_package(archive_path: Path, tmpdir: str) -> Path:
    """Extract a package archive safely. Guards against path traversal,
    symlink attacks, and zip bombs."""
    extract_dir = Path(tmpdir) / 'extracted'
    extract_dir.mkdir(exist_ok=True)
    resolved_root = extract_dir.resolve()

    name = archive_path.name.lower()
    try:
        if name.endswith(('.tgz', '.tar.gz', '.tar.bz2', '.tar')):
            _safe_tar_extract(archive_path, extract_dir, resolved_root)
        elif name.endswith(('.whl', '.zip')):
            _safe_zip_extract(archive_path, extract_dir, resolved_root)
        else:
            raise _UnsafeArchiveError(f"Unsupported archive type: {archive_path.name}")
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
        members = tf.getmembers()
        total_size = 0
        for member in members:
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

        # Safe to extract — reuse validated member list
        safe_members = [m for m in members if m.isfile() or m.isdir()]
        tf.extractall(extract_dir, members=safe_members)


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

        # All entries validated — extract individually (avoid unfiltered extractall)
        for info in zf.infolist():
            zf.extract(info, extract_dir)


def _validate_archive_member(member_name: str, resolved_root: Path, extract_dir: Path) -> None:
    """Reject archive members that would escape the extraction directory."""
    # Normalize and check for path traversal
    if '..' in member_name.split('/') or '..' in member_name.split('\\'):
        raise _UnsafeArchiveError(
            f"Path traversal detected: {member_name}"
        )
    # Resolve the target path and verify it's under the extraction root
    target = (extract_dir / member_name).resolve()
    if not target.is_relative_to(resolved_root):
        raise _UnsafeArchiveError(
            f"Path escapes extraction directory: {member_name}"
        )


# ---------------------------------------------------------------------------
# Top-level vet entry point
# ---------------------------------------------------------------------------

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

    # Warn about public-only registry support
    print(_PRIVATE_REGISTRY_WARNING, file=sys.stderr)

    with tempfile.TemporaryDirectory(prefix='heckler-vet-') as tmpdir:
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
            with contextlib.suppress(ValueError):
                f.file = str(Path(f.file).relative_to(extract_dir))
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
