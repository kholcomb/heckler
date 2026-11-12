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
import zlib
from pathlib import Path
from typing import Self

from .config import Config
from .formatters import get_formatter
from .formatters.text import spell_out
from .scanner import Finding, Scanner

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
    if "==" in spec or ">=" in spec or "<=" in spec or "~=" in spec:
        return "pypi"
    # Scoped npm: @scope/name or @scope/name@version
    if spec.startswith("@"):
        return "npm"
    # Unscoped npm with version: name@version
    if "@" in spec:
        return "npm"
    return "unknown"


def _parse_spec(spec: str, registry: str) -> tuple[str, str | None]:
    """Parse a package spec into (name, version | None).

    For PyPI, only exact-match ``==`` versions are supported; range
    specifiers (``>=``, ``~=``, etc.) cause a hard exit because the
    registry JSON API has no solver.
    """
    if registry == "npm":
        if spec.startswith("@"):
            # Scoped: @scope/name@version — split on the *last* @
            rest = spec[1:]
            if "@" in rest:
                idx = rest.rindex("@")
                return "@" + rest[:idx], rest[idx + 1 :] or None
            return spec, None
        if "@" in spec:
            idx = spec.index("@")
            return spec[:idx], spec[idx + 1 :] or None
        return spec, None

    # PyPI
    for op in (">=", "<=", "~=", "!="):
        if op in spec:
            base = spec.split(op)[0].strip()
            print(
                f"Error: --vet requires an exact version (e.g., {base}==X.Y.Z). "
                f"Version ranges are not supported with direct registry fetching.",
                file=sys.stderr,
            )
            sys.exit(2)
    if "==" in spec:
        name, version = spec.split("==", 1)
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


_MAX_DOWNLOAD_SIZE = 500 * 1024 * 1024  # 500 MB — matches total extraction limit


def _download_file(url: str, dest: Path) -> None:
    """Stream a URL to a local file with a size cap."""
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
        total = 0
        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_DOWNLOAD_SIZE:
                    dest.unlink(missing_ok=True)
                    print(
                        f"Error: Download exceeds {_MAX_DOWNLOAD_SIZE // (1024 * 1024)} MB limit.",
                        file=sys.stderr,
                    )
                    sys.exit(2)
                f.write(chunk)


def _verify_checksum(path: Path, algorithm: str, expected: str, label: str) -> None:
    """Verify a downloaded file's checksum. Exits on mismatch."""
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
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
    encoded = urllib.parse.quote(name, safe="@")
    tag = version if version else "latest"
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

    filename: str = tarball_url.rsplit("/", 1)[-1]
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


def _download_pypi(
    name: str,
    version: str | None,
    tmpdir: str,
    not_scanned: list[tuple[str, str]] | None = None,
) -> list[Path]:
    """Fetch every file of a PyPI release directly from the public registry.

    Which of them pip installs depends on the machine: a wheel if one fits
    the platform and Python version, the sdist otherwise. They are built
    separately and nothing makes their contents agree, so one clean file
    says nothing about the others. All of them are downloaded, the sdist
    first. Downloading and unpacking runs no package code.

    A file in a format heckler cannot unpack (an old ``.exe`` or ``.msi``
    installer, say) is not downloaded; its name and the reason are added to
    *not_scanned*.
    """
    encoded = urllib.parse.quote(name, safe="")
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

    # (not an sdist, filename, url, sha256): sorts the sdist first.
    files: list[tuple[bool, str, str, object]] = []
    for entry in urls:
        download_url = entry.get("url") if isinstance(entry, dict) else None
        filename = entry.get("filename") if isinstance(entry, dict) else None
        if (
            not isinstance(download_url, str)
            or not isinstance(filename, str)
            # The name becomes a path under tmpdir, so it has to be a bare name.
            or "/" in filename
            or "\\" in filename
            or filename in ("", ".", "..")
        ):
            print(f'Error: Malformed download metadata for "{name}".', file=sys.stderr)
            sys.exit(2)
        digests = entry.get("digests")
        sha256 = digests.get("sha256") if isinstance(digests, dict) else None
        files.append((entry.get("packagetype") != "sdist", filename, download_url, sha256))

    download_dir = Path(tmpdir) / "downloads"
    download_dir.mkdir(exist_ok=True)
    archives: list[Path] = []
    for _, filename, download_url, sha256 in sorted(files, key=lambda item: item[:2]):
        dest = download_dir / filename
        if not can_extract(dest):
            if not_scanned is not None:
                not_scanned.append((filename, "heckler cannot unpack this type of file"))
            continue
        try:
            _download_file(download_url, dest)
        except (urllib.error.URLError, OSError) as e:
            print(f"Error: Failed to download {filename}: {e}", file=sys.stderr)
            sys.exit(2)

        if isinstance(sha256, str):
            _verify_checksum(dest, "sha256", sha256, f"{filename} (pypi)")
        archives.append(dest)

    return archives


# ---------------------------------------------------------------------------
# Public download entry point
# ---------------------------------------------------------------------------


def download_package(
    spec: str,
    registry: str,
    tmpdir: str,
    not_scanned: list[tuple[str, str]] | None = None,
) -> list[Path]:
    """Download a package's archives to *tmpdir* via registry API.

    Returns the paths of the downloaded files: the one tarball of an npm
    version, or every file of a PyPI release that heckler can unpack. The
    ones it cannot are named in *not_scanned*.
    """
    name, version = _parse_spec(spec, registry)

    if registry == "npm":
        return [_download_npm(name, version, tmpdir)]
    return _download_pypi(name, version, tmpdir, not_scanned)


# ---------------------------------------------------------------------------
# Archive extraction
# ---------------------------------------------------------------------------

# How many of the files left out as binary the report names.
_MAX_BINARY_LISTED = 20

_TAR_SUFFIXES = (".tgz", ".tar.gz", ".tar.bz2", ".tar")
_ZIP_SUFFIXES = (".whl", ".zip", ".egg")


def can_extract(archive_path: Path) -> bool:
    """Whether :func:`extract_package` knows the archive's format."""
    return archive_path.name.lower().endswith(_TAR_SUFFIXES + _ZIP_SUFFIXES)


def extract_package(archive_path: Path, tmpdir: str) -> Path:
    """Extract a package archive safely. Guards against path traversal,
    symlink attacks, and zip bombs.

    Each archive gets a directory of its own under *tmpdir*, so several can
    be unpacked side by side.
    """
    try:
        return _unpack(archive_path, tmpdir)
    except _ARCHIVE_ERRORS as e:
        print(f"Error: Failed to extract package archive: {e}", file=sys.stderr)
        sys.exit(2)


def _unpack(archive_path: Path, tmpdir: str) -> Path:
    """extract_package() without the exit: an archive that cannot be unpacked raises."""
    extract_dir = Path(tmpdir) / "extracted" / archive_path.name
    extract_dir.mkdir(parents=True, exist_ok=True)
    resolved_root = extract_dir.resolve()

    if not can_extract(archive_path):
        raise _UnsafeArchiveError(f"Unsupported archive type: {archive_path.name}")
    if archive_path.name.lower().endswith(_ZIP_SUFFIXES):
        _safe_zip_extract(archive_path, extract_dir, resolved_root)
    else:
        _safe_tar_extract(archive_path, extract_dir, resolved_root)
    return extract_dir


class _UnsafeArchiveError(Exception):
    """Raised when an archive contains path traversal or symlink attacks."""


# What unpacking an archive raises when the archive is damaged or unsafe.
_ARCHIVE_ERRORS = (
    tarfile.TarError,
    zipfile.BadZipFile,
    zlib.error,
    EOFError,
    OSError,
    _UnsafeArchiveError,
)


# 50 MB uncompressed limit per file to guard against zip bombs
_MAX_EXTRACT_SIZE = 50 * 1024 * 1024
# 500 MB total extraction limit
_MAX_TOTAL_SIZE = 500 * 1024 * 1024
# 1 MB for a header that carries a long name or pax records. A path is a
# few KB at the most, and tarfile reads the whole of such a header into
# memory, whatever size it declares.
_MAX_EXTENDED_HEADER_SIZE = 1024 * 1024

# The headers that are not members: what follows one is the name, the link
# target or the pax records of the member after it.
_EXTENDED_HEADER_TYPES = (
    tarfile.GNUTYPE_LONGNAME,
    tarfile.GNUTYPE_LONGLINK,
    tarfile.XHDTYPE,
    tarfile.XGLTYPE,
    tarfile.SOLARIS_XHDTYPE,
)


def _sparse_file(name: str) -> _UnsafeArchiveError:
    """The refusal of a sparse member.

    Its size is the one its file is said to have. What unpacking copies for
    it is what its map says, read from wherever in the archive that reaches,
    and the file is cut down to the size afterwards. No limit on the size
    holds for that, and a package has no use for a sparse file.
    """
    return _UnsafeArchiveError(f"Archive contains a sparse file: {spell_out(name)}")


class _CheckedTarInfo(tarfile.TarInfo):
    """A tar header that is checked before tarfile reads what it announces.

    tarfile makes every header with frombuf(), a member's or not, and only
    then reads what the header says comes after it. For a long name, for pax
    records and for the map of a sparse file of the older kind it reads all
    of that into memory, before there is a member for _check_tar_sizes()
    to see. So this is where they are refused: from the 512 bytes of the
    header.
    """

    @classmethod
    def frombuf(cls, buf: bytes | bytearray, encoding: str, errors: str) -> Self:
        member = super().frombuf(buf, encoding, errors)
        if member.type == tarfile.GNUTYPE_SPARSE:
            raise _sparse_file(member.name)
        if member.type in _EXTENDED_HEADER_TYPES and member.size > _MAX_EXTENDED_HEADER_SIZE:
            raise _UnsafeArchiveError(f"Header too large ({member.size} bytes)")
        return member


def _check_tar_sizes(tf: tarfile.TarFile) -> None:
    """Refuse an archive whose members declare more than heckler will unpack.

    The size of a regular member is what unpacking writes for it, so the
    headers settle this before anything is written. They are read one at a
    time and the first one over a limit ends it, so an archive made to be
    huge is not walked to its end.

    A sparse member is the one whose size is not what is written. The older
    kind never gets here (see _CheckedTarInfo); the kind that a pax header
    declares is known once the member is read, and is refused here.
    """
    total_size = 0
    for member in tf:
        if member.issparse():
            raise _sparse_file(member.name)
        if member.size < 0:
            # A header can say so, and it would come off the total.
            raise _UnsafeArchiveError(f"Invalid size ({member.size} bytes): {member.name}")
        if member.size > _MAX_EXTRACT_SIZE:
            raise _UnsafeArchiveError(f"File too large ({member.size} bytes): {member.name}")
        total_size += member.size
        if total_size > _MAX_TOTAL_SIZE:
            raise _UnsafeArchiveError(f"Total extraction size exceeds {_MAX_TOTAL_SIZE} bytes")


def _safe_tar_extract(archive_path: Path, extract_dir: Path, resolved_root: Path) -> None:
    """Extract a tar archive with path traversal, symlink and size protection."""
    with tarfile.open(archive_path, tarinfo=_CheckedTarInfo) as tf:
        try:
            # On every Python: filter='data' looks at where a member goes
            # and what kind it is, not at how large it is.
            _check_tar_sizes(tf)
            # filter='data' handles the rest natively. Python 3.11 has it
            # from 3.11.4; before that, we validate manually.
            try:
                tf.extractall(extract_dir, filter="data")
                return
            except TypeError:
                # filter parameter not supported (Python 3.11.0 to 3.11.3)
                pass
        except tarfile.TarError as e:
            # filter='data' raises FilterError subclasses for
            # path traversal, symlinks, etc. Wrap as our error type.
            raise _UnsafeArchiveError(f"Unsafe archive: {e}") from e

        # Manual safe extraction for a Python without the filter
        members = tf.getmembers()
        for member in members:
            _validate_archive_member(member.name, resolved_root, extract_dir)

            if member.issym() or member.islnk():
                raise _UnsafeArchiveError(f"Archive contains symlink/hardlink: {member.name}")
            if member.isdev():
                raise _UnsafeArchiveError(f"Archive contains device file: {member.name}")

        # Safe to extract — reuse validated member list
        safe_members = [m for m in members if m.isfile() or m.isdir()]
        tf.extractall(extract_dir, members=safe_members)


def _safe_zip_extract(archive_path: Path, extract_dir: Path, resolved_root: Path) -> None:
    """Extract a zip archive with path traversal protection."""
    with zipfile.ZipFile(archive_path, "r") as zf:
        total_size = 0
        for info in zf.infolist():
            _validate_archive_member(info.filename, resolved_root, extract_dir)

            if info.file_size > _MAX_EXTRACT_SIZE:
                raise _UnsafeArchiveError(
                    f"File too large ({info.file_size} bytes): {info.filename}"
                )
            total_size += info.file_size
            if total_size > _MAX_TOTAL_SIZE:
                raise _UnsafeArchiveError(f"Total extraction size exceeds {_MAX_TOTAL_SIZE} bytes")

            # Check for symlinks in zip (external_attr encodes Unix mode)
            unix_mode = info.external_attr >> 16
            if unix_mode and (unix_mode & 0o120000) == 0o120000:
                raise _UnsafeArchiveError(f"Archive contains symlink: {info.filename}")

        # All entries validated — extract individually (avoid unfiltered extractall)
        for info in zf.infolist():
            zf.extract(info, extract_dir)


def _validate_archive_member(member_name: str, resolved_root: Path, extract_dir: Path) -> None:
    """Reject archive members that would escape the extraction directory."""
    # Normalize and check for path traversal
    if ".." in member_name.split("/") or ".." in member_name.split("\\"):
        raise _UnsafeArchiveError(f"Path traversal detected: {member_name}")
    # Resolve the target path and verify it's under the extraction root
    target = (extract_dir / member_name).resolve()
    if not target.is_relative_to(resolved_root):
        raise _UnsafeArchiveError(f"Path escapes extraction directory: {member_name}")


# ---------------------------------------------------------------------------
# Top-level vet entry point
# ---------------------------------------------------------------------------


def _inside_archive(path: str, archive: Path, extract_dir: Path) -> str:
    """Name an extracted file by the archive it came from and its path in it."""
    with contextlib.suppress(ValueError):
        path = Path(path).relative_to(extract_dir).as_posix()
    return f"{archive.name}/{path}"


def vet_package(
    spec: str,
    registry_override: str | None,
    config: Config,
    output_format: str = "text",
    color: bool = True,
    quiet: bool = False,
    allow_unscanned: bool = False,
) -> int:
    """Download, scan, and report on a package. Returns exit code.

    Every archive the registry offers for the version is scanned, and every
    text file in each, whatever its extension: a package's executable code
    is not confined to source files (``bin`` scripts without an extension,
    ``.pth`` files). Exit code 2 means some of it could not be scanned,
    unless *allow_unscanned* is set.
    """
    registry = registry_override or detect_registry(spec)
    if registry == "unknown":
        print(
            f'Error: Cannot determine registry for "{spec}". '
            f"Use --registry npm or --registry pypi.",
            file=sys.stderr,
        )
        return 2

    # Warn about public-only registry support
    print(_PRIVATE_REGISTRY_WARNING, file=sys.stderr)

    findings: list[Finding] = []
    scanned: list[str] = []
    not_scanned: list[tuple[str, str]] = []
    binary: list[str] = []

    with tempfile.TemporaryDirectory(prefix="heckler-vet-") as tmpdir:
        archives = download_package(spec, registry, tmpdir, not_scanned)

        scanner = Scanner(
            skip_dirs=frozenset(),  # Don't skip anything in extracted package
            all_text=True,  # nor any text file, whatever it is called
            severity_threshold=config.severity_threshold,
            exclude_patterns=config.exclude_patterns,
            allow_bom=config.allow_bom,
            allow_emoji=config.allow_emoji,
            scan_deps=True,
        )

        for archive in archives:
            try:
                extract_dir = _unpack(archive, tmpdir)
            except _ARCHIVE_ERRORS as e:
                # Part of the package that nobody looked at. The report says
                # so, and the other files of the package are still scanned.
                not_scanned.append((archive.name, f"it could not be unpacked ({e})"))
                continue
            already_skipped, already_binary = len(scanner.skipped), len(scanner.binary)
            for f in scanner.scan_path(extract_dir):
                f.file = _inside_archive(f.file, archive, extract_dir)
                f.source = "dependency"
                f.package = spec
                findings.append(f)
            scanned.append(archive.name)
            not_scanned.extend(
                (_inside_archive(path, archive, extract_dir), reason)
                for path, reason in scanner.skipped[already_skipped:]
            )
            binary.extend(
                _inside_archive(path, archive, extract_dir)
                for path in scanner.binary[already_binary:]
            )

    for name, reason in not_scanned:
        print(f"Warning: {name} was not scanned: {reason}", file=sys.stderr)

    formatter = get_formatter(output_format)
    output = formatter(findings, color=color, quiet=quiet)

    # Prepend vet summary header
    if output_format == "text":
        files = f"{len(scanned)} file(s) scanned"
        if findings:
            counts: dict[str, int] = {}
            for f in findings:
                sev = f.severity.value.upper()
                counts[sev] = counts.get(sev, 0) + 1
            count_str = ", ".join(f"{v} {k}" for k, v in counts.items())
            verdict = f"{len(findings)} finding(s) ({count_str}). DO NOT INSTALL."
        elif not_scanned:
            verdict = f"0 findings, {len(not_scanned)} file(s) not scanned. INCOMPLETE."
        else:
            verdict = "0 findings. CLEAN."
        print(f"[VET] {spec} ({registry}) — {files}, {verdict}")
        if not quiet:
            for name in scanned:
                print(f"  scanned: {name}")
            for name, _reason in not_scanned:
                print(f"  not scanned: {name}")
            # Content decides what is binary, and the package wrote the
            # content. Naming the files lets a reader see what that left out,
            # of a file that was scanned for the text inside it as well.
            for name in binary[:_MAX_BINARY_LISTED]:
                print(f"  binary, not scanned as text: {name}")
            if len(binary) > _MAX_BINARY_LISTED:
                more = len(binary) - _MAX_BINARY_LISTED
                print(f"  binary, not scanned as text: {more} more file(s)")

    # "Nothing found" would be the wrong thing to say when part of the
    # package was never looked at; the header and warnings tell that story.
    nothing_was_checked = output_format == "text" and not_scanned and not findings
    if output and not nothing_was_checked:
        print(output)

    if findings:
        return 1
    if not_scanned and not allow_unscanned:
        print(
            f"Error: {len(not_scanned)} file(s) of {spec} could not be scanned (see the"
            " warnings above). Pass --allow-unscanned to accept this.",
            file=sys.stderr,
        )
        return 2
    return 0
