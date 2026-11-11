"""Lockfile diff parsing for targeted dependency scanning.

Parses staged lockfile diffs to identify changed packages, then scans
only those package directories — fast enough for pre-commit (<2s).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

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


def get_lockfile_diff(lockfile_path: str) -> str:
    """Get the staged diff for a lockfile."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", _FULL_CONTEXT, "--", lockfile_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout
        # Fall back to unstaged diff
        result = subprocess.run(
            ["git", "diff", _FULL_CONTEXT, "--", lockfile_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.stdout if result.returncode == 0 else ""
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


def resolve_package_dir(
    pkg_name: str,
    ecosystem: str,
    lockfile_path: str,
) -> Path | None:
    """Map a package name to its install directory."""
    lockfile_dir = Path(lockfile_path).parent

    if ecosystem in ("npm", "yarn", "pnpm"):
        # Check local node_modules, then walk up for hoisted
        candidate = lockfile_dir / "node_modules" / pkg_name
        if candidate.is_dir():
            return candidate
        # Walk up for yarn/npm workspaces
        current = lockfile_dir.parent
        for _ in range(5):
            candidate = current / "node_modules" / pkg_name
            if candidate.is_dir():
                return candidate
            if current.parent == current:
                break
            current = current.parent
        return None

    elif ecosystem in ("pip", "poetry", "pipenv"):
        # Try to find site-packages
        try:
            result = subprocess.run(
                [sys.executable, "-c", 'import site; print("\\n".join(site.getsitepackages()))'],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                for sp in result.stdout.strip().splitlines():
                    candidate = Path(sp) / pkg_name
                    if candidate.is_dir():
                        return candidate
                    # Try with underscores (pip normalizes hyphens)
                    candidate = Path(sp) / pkg_name.replace("-", "_")
                    if candidate.is_dir():
                        return candidate
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    return None


def scan_changed_deps(lockfile_paths: list[str], scanner: Scanner) -> list[Finding]:
    """Main entry point: parse lockfile diffs and scan only changed packages."""
    all_findings: list[Finding] = []

    for lf_path in lockfile_paths:
        ecosystem = detect_ecosystem(lf_path)
        if ecosystem == "unknown":
            print(f"Warning: Unknown lockfile format: {lf_path}", file=sys.stderr)
            continue

        diff_text = get_lockfile_diff(lf_path)
        if not diff_text:
            # No diff — try scanning the lockfile's dependency dir entirely
            print(f"Warning: No diff available for {lf_path}. Skipping.", file=sys.stderr)
            continue

        changed = parse_changed_packages(diff_text, ecosystem)
        if not changed:
            continue

        for pkg_name, _version in changed:
            pkg_dir = resolve_package_dir(pkg_name, ecosystem, lf_path)
            if pkg_dir is None:
                print(
                    f"Warning: {pkg_name} changed in {lf_path} but install directory not found. "
                    f"Run your package manager's install command and re-commit.",
                    file=sys.stderr,
                )
                continue
            findings = scanner.scan_path(pkg_dir)
            # Tag findings with package info
            for f in findings:
                f.source = "dependency"
                f.package = pkg_name
            all_findings.extend(findings)

    return all_findings
