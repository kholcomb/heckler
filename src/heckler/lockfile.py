"""Lockfile diff parsing for targeted dependency scanning.

Parses staged lockfile diffs to identify changed packages, then scans
only the installed copies of those packages — fast enough for pre-commit
(<2s). A changed package that is not installed, or is installed at a
different version than the lockfile names, is reported as unscanned
rather than passed over.
"""

from __future__ import annotations

import csv
import functools
import json
import os
import re
import site
import subprocess
import sys
import sysconfig
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from .scanner import DEP_SCAN_EXTENSIONS

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from .scanner import Finding, Scanner

# Ask git for the whole file as context. The parsers walk the new side of the
# diff and attribute each added line to the package block it sits in. With the
# default three lines, a version bump shows only the changed "version" and
# "resolved" lines and the package name may not appear in the diff at all.
_FULL_CONTEXT = "--unified=1000000"


def detect_ecosystem(lockfile_path: str) -> str:
    """Determine ecosystem from lockfile name."""
    name = Path(lockfile_path).name.lower()
    mapping = {
        "package-lock.json": "npm",
        "yarn.lock": "yarn",
        "pnpm-lock.yaml": "pnpm",
        "requirements.txt": "pip",
        "poetry.lock": "poetry",
        "pipfile.lock": "pipenv",
        "cargo.lock": "cargo",
        "go.sum": "go",
        "gemfile.lock": "ruby",
        "composer.lock": "composer",
    }
    return mapping.get(name, "unknown")


def _git_diff(*args: str) -> str:
    result = subprocess.run(
        ["git", "diff", _FULL_CONTEXT, *args],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout if result.returncode == 0 else ""


def get_lockfile_diff(lockfile_path: str) -> str:
    """Get the diff for a lockfile.

    The staged diff comes first, then the unstaged one. When neither exists
    and pre-commit is checking a range of commits (a push hook, or
    ``pre-commit run --from-ref ... --to-ref ...`` in CI), the diff across
    that range is used.
    """
    try:
        diff = _git_diff("--cached", "--", lockfile_path) or _git_diff("--", lockfile_path)
        if diff:
            return diff
        from_ref = os.environ.get("PRE_COMMIT_FROM_REF", "")
        to_ref = os.environ.get("PRE_COMMIT_TO_REF", "")
        if from_ref and to_ref and not from_ref.startswith("-") and not to_ref.startswith("-"):
            return _git_diff(f"{from_ref}...{to_ref}", "--", lockfile_path)
        return ""
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def parse_changed_packages(diff_text: str, ecosystem: str) -> list[tuple[str, str]]:
    """Parse a lockfile diff to extract (name, version) tuples for added/changed packages."""
    if ecosystem == "npm":
        return _parse_npm_lockfile_diff(diff_text)
    elif ecosystem == "pip":
        return _parse_pip_diff(diff_text)
    elif ecosystem == "poetry":
        return _parse_poetry_diff(diff_text)
    elif ecosystem == "yarn":
        return _parse_yarn_diff(diff_text)
    elif ecosystem == "pnpm":
        return _parse_pnpm_diff(diff_text)
    elif ecosystem == "pipenv":
        return _parse_pipfile_lock_diff(diff_text)
    elif ecosystem in ("cargo", "go", "ruby", "composer"):
        print(
            f"Warning: {ecosystem} lockfile parsing is not yet supported. "
            f"Changed packages will not be scanned with --diff-only.",
            file=sys.stderr,
        )
        return []
    return []


class _Changes:
    """Lockfile entries that changed, in first-seen order.

    Parsers mark an entry when one of its lines was added and record its
    name and version as they come across them, in whatever order the format
    puts them. An entry without a name is not a package and is dropped.
    """

    def __init__(self) -> None:
        self._marked: dict[str, None] = {}
        self._names: dict[str, str] = {}
        self._versions: dict[str, str] = {}
        self._skipped: set[str] = set()

    def mark(self, key: str) -> None:
        self._marked.setdefault(key)

    def set_name(self, key: str, name: str) -> None:
        self._names[key] = name

    def set_version(self, key: str, version: str) -> None:
        self._versions[key] = version

    def skip(self, key: str) -> None:
        self._skipped.add(key)

    def result(self) -> list[tuple[str, str]]:
        pairs = [
            (self._names[key], self._versions.get(key, ""))
            for key in self._marked
            if key in self._names and key not in self._skipped
        ]
        return list(dict.fromkeys(pairs))


def _new_side(diff_text: str) -> Iterator[tuple[bool, str]]:
    """Yield ``(added, text)`` for each line on the new side of a unified diff.

    Removed lines and diff headers are dropped, so the caller sees the
    lockfile as it stands after the change, with every line marked as added
    or unchanged.
    """
    for line in diff_text.splitlines():
        if line.startswith("+++"):
            continue
        if line.startswith("+"):
            yield True, line[1:]
        elif line.startswith(" "):
            yield False, line[1:]


def _indent(text: str) -> int:
    return len(text) - len(text.lstrip())


_NPM_PACKAGE_KEY_RE = re.compile(r'^(\s*)"node_modules/([^"]+)": \{\s*$')
_JSON_OBJECT_KEY_RE = re.compile(r'^(\s*)"([^"]+)": \{\s*$')
_JSON_VERSION_RE = re.compile(r'^\s*"version": "([^"]+)",?\s*$')
_JSON_LINK_RE = re.compile(r'^\s*"link": true,?\s*$')


def _parse_npm_lockfile_diff(diff_text: str) -> list[tuple[str, str]]:
    """Parse a package-lock.json diff for added or changed packages.

    A package counts as changed when any line inside its
    ``"node_modules/<name>": {`` block was added, which covers both new
    entries and version bumps of existing ones. Workspace links are left
    out: they point at the project's own code.
    """
    changes = _Changes()
    current: str | None = None
    current_indent = 0
    field_indent = -1
    for added, text in _new_side(diff_text):
        if not text.strip():
            continue
        indent = _indent(text)
        m = _NPM_PACKAGE_KEY_RE.match(text)
        if m:
            current, current_indent, field_indent = m.group(2), len(m.group(1)), -1
            changes.set_name(current, current)
        elif indent <= current_indent:
            # The closing brace, the root "" entry, a workspace entry, or
            # the end of "packages": no longer inside a package block.
            current = None
        elif current is not None:
            if field_indent < 0:
                field_indent = indent
            if indent == field_indent:
                version = _JSON_VERSION_RE.match(text)
                if version:
                    changes.set_version(current, version.group(1))
                elif _JSON_LINK_RE.match(text):
                    changes.skip(current)
        if added and current is not None:
            changes.mark(current)
    return changes.result()


_REQUIREMENT_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(==|>=|<=|!=|~=)\s*([^\s;\\#,]*)"
)


def _parse_pip_diff(diff_text: str) -> list[tuple[str, str]]:
    """Parse a requirements.txt diff for added packages.

    Only an exact ``==`` pin yields a version; for a range the installed
    version cannot be checked against the file.
    """
    packages: list[tuple[str, str]] = []
    for line in diff_text.splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        m = _REQUIREMENT_RE.match(line[1:].strip())
        if not m:
            continue  # comments, options such as -r and --hash, blank lines
        name, operator, version = m.groups()
        packages.append((name.lower(), version if operator == "==" else ""))
    return list(dict.fromkeys(packages))


_POETRY_NAME_RE = re.compile(r'^name\s*=\s*["\']([^"\']+)["\']')
_POETRY_VERSION_RE = re.compile(r'^version\s*=\s*["\']([^"\']+)["\']')


def _parse_poetry_diff(diff_text: str) -> list[tuple[str, str]]:
    """Parse a poetry.lock diff for added or changed packages.

    Each ``[[package]]`` table, together with its ``[package.*]`` sub-tables,
    is one block; a package counts as changed when any line in its block was
    added.
    """
    changes = _Changes()
    block = 0
    key: str | None = None
    in_header = False  # between "[[package]]" and its first sub-table
    for added, text in _new_side(diff_text):
        stripped = text.strip()
        if not stripped:
            continue
        if stripped == "[[package]]":
            block += 1
            key, in_header = str(block), True
        elif stripped.startswith("["):
            in_header = False
            if not stripped.startswith("[package."):
                key = None  # [metadata], [extras], ...
        elif in_header and key is not None:
            name = _POETRY_NAME_RE.match(stripped)
            version = _POETRY_VERSION_RE.match(stripped)
            if name:
                changes.set_name(key, name.group(1).lower())
            elif version:
                changes.set_version(key, version.group(1))
        if added and key is not None:
            changes.mark(key)
    return changes.result()


def _yarn_entry_name(header: str) -> str | None:
    """Extract the package name from a yarn.lock entry header, if it is one.

    Handles classic (``"lodash@^4.0.0", "lodash@^4.17.0":``) and berry
    (``"lodash@npm:^4.17.21":``) headers.
    """
    header = header.strip()
    if not header.endswith(":") or "@" not in header:
        return None
    spec = header[:-1].split(",")[0].strip().strip('"').strip("'")
    if "@workspace:" in spec:
        return None  # the project's own packages, not installed dependencies
    if spec.startswith("@"):
        # Scoped: @scope/name@range
        return "@" + spec[1:].split("@", 1)[0]
    return spec.split("@", 1)[0]


_YARN_VERSION_RE = re.compile(r'^  version:?\s+"?([^"\s]+)"?\s*$')


def _parse_yarn_diff(diff_text: str) -> list[tuple[str, str]]:
    """Parse a yarn.lock diff for added or changed packages.

    An entry runs from its unindented header to the next unindented line; a
    package counts as changed when any line in its entry was added.
    """
    changes = _Changes()
    key: str | None = None
    for added, text in _new_side(diff_text):
        if not text.strip():
            continue
        if not text[0].isspace():
            name = _yarn_entry_name(text)
            key = text.strip() if name else None
            if key is not None and name:
                changes.set_name(key, name)
        elif key is not None:
            version = _YARN_VERSION_RE.match(text)
            if version:
                changes.set_version(key, version.group(1))
        if added and key is not None:
            changes.mark(key)
    return changes.result()


def _pnpm_key_to_package(key: str) -> tuple[str, str] | None:
    """Split a pnpm-lock.yaml package key into ``(name, version)``.

    The key format changed with the lockfile version:

    - v5: ``/lodash/4.17.21``, ``/@scope/pkg/1.0.0_react@17.0.2``
    - v6: ``/lodash@4.17.21``, ``/@scope/pkg@1.0.0(react@17.0.2)``
    - v9: ``lodash@4.17.21``, ``'@scope/pkg@1.0.0(react@17.0.2)'``
    """
    key = key.strip().strip("'\"").lstrip("/").split("(", 1)[0]
    scoped = key.startswith("@")
    body = key[1:] if scoped else key
    if not body:
        return None
    name_slashes = 1 if scoped else 0
    if body.split("@", 1)[0].count("/") > name_slashes:
        # v5: the version is its own path segment.
        parts = body.split("/")
        name = "/".join(parts[: name_slashes + 1])
        version = parts[name_slashes + 1].split("_", 1)[0]
    else:
        name, _, version = body.partition("@")
    if not name:
        return None
    if ":" in version or "/" in version:
        version = ""  # a git, file or tarball reference rather than a release
    return ("@" if scoped else "") + name, version


def _parse_pnpm_diff(diff_text: str) -> list[tuple[str, str]]:
    """Parse a pnpm-lock.yaml diff for added or changed packages.

    Package entries are the two-space-indented keys of the top-level
    ``packages`` section and, from lockfile v9, ``snapshots``. Other
    sections, such as ``importers``, describe the project itself.
    """
    changes = _Changes()
    section: str | None = None  # unknown until a top-level key is seen
    key: str | None = None
    for added, text in _new_side(diff_text):
        stripped = text.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = _indent(text)
        if indent == 0:
            section, key = stripped.rstrip(":"), None
            continue
        if section not in (None, "packages", "snapshots"):
            continue
        if indent == 2:
            key = None
            entry = stripped[:-1] if stripped.endswith(":") else ""
            # A diff with no context has no section header to go by, so the
            # key has to look like a package: "/name..." or "name@version".
            if entry and (section is not None or entry.startswith("/") or "@" in entry[1:]):
                package = _pnpm_key_to_package(entry)
                if package:
                    key = entry
                    changes.set_name(key, package[0])
                    changes.set_version(key, package[1])
        if added and key is not None:
            changes.mark(key)
    return changes.result()


def _parse_pipfile_lock_diff(diff_text: str) -> list[tuple[str, str]]:
    """Parse a Pipfile.lock diff for added or changed packages.

    Packages are the keys of the ``default`` and ``develop`` objects; a
    package counts as changed when any line in its object was added.
    """
    changes = _Changes()
    section = ""
    section_indent = -1  # indent of "default" / "develop" while inside one
    package_indent = -1
    key: str | None = None
    for added, text in _new_side(diff_text):
        if not text.strip():
            continue
        indent = _indent(text)
        m = _JSON_OBJECT_KEY_RE.match(text)
        if section_indent >= 0 and indent <= section_indent:
            section_indent, package_indent, key = -1, -1, None
        if section_indent < 0:
            if m and m.group(2) in ("default", "develop"):
                section, section_indent = m.group(2), indent
            continue
        if package_indent < 0:
            package_indent = indent
        if indent == package_indent:
            key = f"{section}:{m.group(2)}" if m else None
            if key is not None and m:
                changes.set_name(key, m.group(2).lower())
        elif key is not None:
            version = _JSON_VERSION_RE.match(text)
            if version:
                changes.set_version(key, version.group(1).lstrip("="))
        if added and key is not None:
            changes.mark(key)
    return changes.result()


# ---------------------------------------------------------------------------
# Locating the installed copy of a changed package
# ---------------------------------------------------------------------------

_NODE_ECOSYSTEMS = ("npm", "yarn", "pnpm")
_PYTHON_ECOSYSTEMS = ("pip", "poetry", "pipenv")
_VENV_DIR_NAMES = (".venv", "venv", "env")
_MAX_PATH_INTERPRETERS = 4

_SITE_PACKAGES_QUERY = (
    "import site, sysconfig; p = sysconfig.get_paths(); "
    "print(p['purelib']); print(p['platlib']); "
    "print(site.getusersitepackages() if site.ENABLE_USER_SITE else '')"
)


def _node_installed_version(pkg_dir: Path) -> str | None:
    try:
        data = json.loads((pkg_dir / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    version = data.get("version") if isinstance(data, dict) else None
    return version if isinstance(version, str) else None


def _node_candidates(
    pkg_name: str, version: str, ecosystem: str, lockfile_dir: Path
) -> Iterator[Path]:
    """Directories where a node package may be installed, most likely first."""
    yield lockfile_dir / "node_modules" / pkg_name
    # Walk up for installs hoisted to a yarn/npm workspace root.
    current = lockfile_dir.parent
    for _ in range(5):
        yield current / "node_modules" / pkg_name
        if current.parent == current:
            break
        current = current.parent

    modules = lockfile_dir / "node_modules"
    if ecosystem == "pnpm" and version:
        # pnpm keeps every package in a virtual store and links only the
        # direct dependencies into node_modules itself.
        store_name = pkg_name.replace("/", "+")
        for entry in sorted(modules.glob(f".pnpm/{store_name}@{version}*")):
            yield entry / "node_modules" / pkg_name
    if ecosystem == "yarn":
        # A second version of a package is nested under what depends on it.
        yield from sorted(modules.glob(f"*/node_modules/{pkg_name}"))
        yield from sorted(modules.glob(f"@*/*/node_modules/{pkg_name}"))


def _resolve_node(
    pkg_name: str, version: str, ecosystem: str, lockfile_dir: Path
) -> tuple[list[Path], str]:
    other_versions: list[str] = []
    for candidate in _node_candidates(pkg_name, version, ecosystem, lockfile_dir):
        if not candidate.is_dir():
            continue
        installed = _node_installed_version(candidate)
        if version and installed and installed != version:
            other_versions.append(installed)
            continue
        return [candidate], ""
    if other_versions:
        return [], f"the installed version is {other_versions[0]}"
    return [], "it is not installed"


def _venv_site_packages(venv: Path) -> list[Path]:
    found = sorted(venv.glob("lib*/python*/site-packages"))
    windows_layout = venv / "Lib" / "site-packages"
    if windows_layout.is_dir():
        found.append(windows_layout)
    return found


def _own_site_packages() -> list[Path]:
    paths = sysconfig.get_paths()
    dirs = [paths["purelib"], paths["platlib"]]
    if site.ENABLE_USER_SITE:
        dirs.append(site.getusersitepackages())
    return [Path(d) for d in dirs]


def _query_interpreter(executable: str) -> list[Path]:
    try:
        result = subprocess.run(
            [executable, "-c", _SITE_PACKAGES_QUERY],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    if result.returncode != 0:
        return []
    return [Path(line) for line in result.stdout.splitlines() if line.strip()]


@functools.lru_cache(maxsize=1)
def _path_site_packages() -> tuple[Path, ...]:
    """Site-packages of the other Python interpreters on PATH.

    Under pre-commit heckler runs from its own isolated environment, which
    never holds the project's dependencies. pre-commit puts that environment
    first on PATH and leaves the rest as it was, so a virtualenv that was
    active when the commit started is still there to be found.
    """
    own_bin = os.path.dirname(os.path.abspath(sys.executable))
    names = ("python.exe",) if os.name == "nt" else ("python3", "python")
    found: list[Path] = []
    queried = 0
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory or os.path.abspath(directory) == own_bin:
            continue
        for name in names:
            executable = os.path.join(directory, name)
            if os.path.isfile(executable) and os.access(executable, os.X_OK):
                found.extend(_query_interpreter(executable))
                queried += 1
                break
        if queried >= _MAX_PATH_INTERPRETERS:
            break
    return tuple(found)


def _python_site_packages(lockfile_dir: Path) -> Iterator[Path]:
    """Site-packages directories that may hold the project's dependencies.

    Cheapest and most specific first: a virtualenv next to the lockfile or in
    the working directory, then the environment heckler itself runs in, then
    whatever other interpreters are on PATH.
    """
    seen: set[Path] = set()

    def fresh(paths: Iterable[Path]) -> Iterator[Path]:
        for path in paths:
            resolved = path.resolve()
            if resolved not in seen and path.is_dir():
                seen.add(resolved)
                yield path

    for base in (lockfile_dir, Path.cwd()):
        for name in _VENV_DIR_NAMES:
            venv = base / name
            if (venv / "pyvenv.cfg").is_file():
                yield from fresh(_venv_site_packages(venv))
    yield from fresh(_own_site_packages())
    yield from fresh(_path_site_packages())


def _normalize_dist_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _same_python_version(left: str, right: str) -> bool:
    """Compare two version strings the way ``==`` does, ignoring zero padding."""

    def normalize(version: str) -> str:
        version = version.strip().lower().lstrip("v").split("+", 1)[0]
        m = re.match(r"^(\d+(?:\.\d+)*)(.*)$", version)
        if not m:
            return version
        release = m.group(1).split(".")
        while len(release) > 1 and release[-1] == "0":
            release.pop()
        return ".".join(release) + re.sub(r"[-_.]", "", m.group(2))

    return normalize(left) == normalize(right)


def _find_distributions(site_packages: Path, name: str) -> list[tuple[Path, str]]:
    """Installed distributions of *name*, as ``(metadata path, version)``.

    The import name of a package is often not its distribution name (PyYAML
    installs ``yaml``), so the lookup goes through the ``.dist-info`` and
    ``.egg-info`` entries that installers leave behind.
    """
    wanted = _normalize_dist_name(name)
    try:
        entries = sorted(site_packages.iterdir())
    except OSError:
        return []
    found: list[tuple[Path, str]] = []
    for entry in entries:
        if entry.suffix not in (".dist-info", ".egg-info"):
            continue
        parts = entry.name[: -len(entry.suffix)].split("-")
        if _normalize_dist_name(parts[0]) == wanted:
            found.append((entry, parts[1] if len(parts) > 1 else ""))
    return found


def _distribution_files(site_packages: Path, metadata: Path) -> list[Path]:
    """What a distribution installed that is worth scanning.

    ``RECORD`` lists every installed file, which keeps the scan to this one
    distribution even when it shares a namespace directory with others.
    Without it, ``top_level.txt`` names the modules and packages.
    """
    record = metadata / "RECORD"
    if record.is_file():
        files: list[Path] = []
        try:
            with open(record, encoding="utf-8", newline="") as f:
                rows = [row for row in csv.reader(f) if row]
        except (OSError, UnicodeDecodeError, csv.Error):
            rows = []
        for row in rows:
            relative = PurePosixPath(row[0])
            if relative.is_absolute() or ".." in relative.parts:
                continue  # scripts and data installed outside site-packages
            path = site_packages.joinpath(*relative.parts)
            if path.suffix.lower() in DEP_SCAN_EXTENSIONS and path.is_file():
                files.append(path)
        return files

    targets: list[Path] = []
    top_level = metadata / "top_level.txt"
    if top_level.is_file():
        try:
            modules = top_level.read_text(encoding="utf-8").split()
        except (OSError, UnicodeDecodeError):
            modules = []
        for module in modules:
            if (site_packages / module).is_dir():
                targets.append(site_packages / module)
            elif (site_packages / f"{module}.py").is_file():
                targets.append(site_packages / f"{module}.py")
    return targets


def _resolve_python(pkg_name: str, version: str, lockfile_dir: Path) -> tuple[list[Path], str]:
    other_versions: list[str] = []
    for site_packages in _python_site_packages(lockfile_dir):
        for metadata, installed in _find_distributions(site_packages, pkg_name):
            if version and installed and not _same_python_version(installed, version):
                other_versions.append(installed)
                continue
            return _distribution_files(site_packages, metadata), ""
    if other_versions:
        return [], f"the installed version is {other_versions[0]}"

    # No installer metadata anywhere: fall back to a directory named after
    # the package, which is all that can be said about such an install.
    for site_packages in _python_site_packages(lockfile_dir):
        for guess in (pkg_name, pkg_name.replace("-", "_")):
            if (site_packages / guess).is_dir():
                return [site_packages / guess], ""
    return [], "it is not installed"


def resolve_package(
    pkg_name: str, version: str, ecosystem: str, lockfile_path: str
) -> tuple[list[Path], str]:
    """Find what to scan for a package that changed in a lockfile.

    Returns ``(targets, problem)``. *targets* are directories or files to
    scan and may be empty for a package that ships nothing scannable.
    *problem* is empty on success; otherwise it says why the package cannot
    be scanned, which is the case when it is not installed or when the
    installed copy is a different version than the lockfile names.
    """
    lockfile_dir = Path(lockfile_path).parent
    if ecosystem in _NODE_ECOSYSTEMS:
        return _resolve_node(pkg_name, version, ecosystem, lockfile_dir)
    if ecosystem in _PYTHON_ECOSYSTEMS:
        return _resolve_python(pkg_name, version, lockfile_dir)
    return [], f"{ecosystem} packages cannot be located"


def resolve_package_dir(
    pkg_name: str,
    ecosystem: str,
    lockfile_path: str,
) -> Path | None:
    """Map a package name to its install directory, if it has one."""
    targets, _problem = resolve_package(pkg_name, "", ecosystem, lockfile_path)
    return next((target for target in targets if target.is_dir()), None)


def scan_changed_deps(
    lockfile_paths: list[str],
    scanner: Scanner,
    unscanned: list[str] | None = None,
) -> list[Finding]:
    """Main entry point: parse lockfile diffs and scan only changed packages.

    A changed package that cannot be scanned is reported on stderr and, when
    *unscanned* is given, described there so the caller can fail the run.
    """
    all_findings: list[Finding] = []

    for lf_path in lockfile_paths:
        ecosystem = detect_ecosystem(lf_path)
        if ecosystem == "unknown":
            print(f"Warning: Unknown lockfile format: {lf_path}", file=sys.stderr)
            continue

        diff_text = get_lockfile_diff(lf_path)
        if not diff_text:
            print(f"Warning: No diff available for {lf_path}. Skipping.", file=sys.stderr)
            continue

        for pkg_name, version in parse_changed_packages(diff_text, ecosystem):
            targets, problem = resolve_package(pkg_name, version, ecosystem, lf_path)
            if problem:
                label = f"{pkg_name} {version}".strip()
                message = f"{label} changed in {lf_path} but was not scanned: {problem}"
                print(f"Warning: {message}", file=sys.stderr)
                if unscanned is not None:
                    unscanned.append(message)
                continue
            for target in targets:
                findings = scanner.scan_path(target)
                # Tag findings with package info
                for f in findings:
                    f.source = "dependency"
                    f.package = pkg_name
                all_findings.extend(findings)

    return all_findings
