"""Lockfile diff parsing for targeted dependency scanning.

Parses staged lockfile diffs to identify changed packages, then scans
only the installed copies of those packages — fast enough for pre-commit
(<2s). Whatever could not be checked is reported as unscanned rather than
passed over: a changed package that is not installed, or is installed at a
different version than the lockfile names, a lockfile in a format heckler
does not read, and a line of a requirements file it cannot make sense of.
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
from typing import TYPE_CHECKING, NamedTuple, cast

from .formatters.text import spell_out
from .scanner import Scanner

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from .scanner import Finding

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
    if name.startswith("requirements") and name.endswith(".txt"):
        return "pip"  # requirements-dev.txt, requirements_test.txt, ...
    return mapping.get(name, "unknown")


# Lockfiles that are recognised by name but have no parser yet.
_UNPARSED_ECOSYSTEMS = ("cargo", "go", "ruby", "composer")


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


def parse_changed_packages(
    diff_text: str, ecosystem: str, problems: list[str] | None = None
) -> list[tuple[str, str]]:
    """Parse a lockfile diff to extract (name, version) tuples for added/changed packages.

    Parts of the diff that could not be read are described in *problems*,
    when it is given: a package behind one of those was not found, so the
    caller has nothing to scan for it.
    """
    if ecosystem == "npm":
        return _parse_npm_lockfile_diff(diff_text, problems)
    elif ecosystem == "pip":
        return _parse_pip_diff(diff_text, problems)
    elif ecosystem == "poetry":
        return _parse_poetry_diff(diff_text)
    elif ecosystem == "yarn":
        return _parse_yarn_diff(diff_text)
    elif ecosystem == "pnpm":
        return _parse_pnpm_diff(diff_text)
    elif ecosystem == "pipenv":
        return _parse_pipfile_lock_diff(diff_text)
    elif ecosystem in _UNPARSED_ECOSYSTEMS:
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
_NPM_LOCKFILE_VERSION_RE = re.compile(r'^\s*"lockfileVersion": (\d+),?\s*$')
_JSON_OBJECT_KEY_RE = re.compile(r'^(\s*)"([^"]+)": \{\s*$')
_JSON_VERSION_RE = re.compile(r'^\s*"version": "([^"]+)",?\s*$')
_JSON_LINK_RE = re.compile(r'^\s*"link": true,?\s*$')
_JSON_CLOSING_LINES = ("}", "},")


def _parse_npm_lockfile_diff(
    diff_text: str, problems: list[str] | None = None
) -> list[tuple[str, str]]:
    """Parse a package-lock.json diff for added or changed packages.

    Versions 2 and 3 list every package under ``"packages"``; version 1 has
    only the ``"dependencies"`` tree. A version heckler does not know is
    reported in *problems* rather than guessed at.
    """
    lines = [(added, text) for added, text in _new_side(diff_text) if text.strip()]
    version = next(
        (int(m.group(1)) for _, text in lines if (m := _NPM_LOCKFILE_VERSION_RE.match(text))),
        None,
    )
    if version == 1:
        return _parse_npm_dependency_tree(lines)
    if version is not None and version not in (2, 3):
        if problems is not None and any(added for added, _ in lines):
            problems.append(
                f"lockfileVersion {version} is not one heckler can read,"
                " so the packages it changes were not scanned"
            )
        return []
    # Version 2 or 3, or a diff without enough context to show the version.
    return _parse_npm_packages(lines)


def _parse_npm_packages(lines: list[tuple[bool, str]]) -> list[tuple[str, str]]:
    """Changed packages in the ``"packages"`` section of lockfile v2 and v3.

    A package counts as changed when any line inside its
    ``"node_modules/<name>": {`` block was added, which covers both new
    entries and version bumps of existing ones. Workspace links are left
    out: they point at the project's own code.
    """
    changes = _Changes()
    current: str | None = None
    current_indent = 0
    field_indent = -1
    for added, text in lines:
        indent = _indent(text)
        m = _NPM_PACKAGE_KEY_RE.match(text)
        if m:
            name: str = m.group(2)
            current, current_indent, field_indent = name, len(m.group(1)), -1
            changes.set_name(name, name)
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


def _parse_npm_dependency_tree(lines: list[tuple[bool, str]]) -> list[tuple[str, str]]:
    """Changed packages in the ``"dependencies"`` tree of lockfile v1.

    The tree mirrors ``node_modules``: a package that could not be hoisted
    sits in the ``"dependencies"`` of the package that needs it and is
    installed in that package's own ``node_modules``. Names are returned as
    install paths (``express/node_modules/debug``), as they are for v2 and
    v3. A package counts as changed when a line of its own block was added;
    a change inside a nested package belongs to that package alone.
    """
    changes = _Changes()
    # The objects the current line is inside, innermost last, as
    # (indent, kind, install path). A "tree" holds packages, a "package"
    # holds its fields, and "other" is anything else, such as "requires".
    stack: list[tuple[int, str, str]] = []
    for added, text in lines:
        indent = _indent(text)
        while stack and indent <= stack[-1][0]:
            stack.pop()
        kind, path = (stack[-1][1], stack[-1][2]) if stack else ("root", "")

        m = _JSON_OBJECT_KEY_RE.match(text)
        if m:
            key = m.group(2)
            if kind == "tree":
                path = f"{path}/node_modules/{key}" if path else key
                stack.append((indent, "package", path))
                changes.set_name(path, path)
            elif kind in ("root", "package") and key == "dependencies":
                stack.append((indent, "tree", path))
            else:
                stack.append((indent, "other", path))
        elif kind == "package":
            version = _JSON_VERSION_RE.match(text)
            if version:
                # "github:user/repo#ref", "file:../lib", a tarball URL: there
                # is no release number to compare the install against.
                release = version.group(1)
                changes.set_version(path, "" if ":" in release or "/" in release else release)

        if added and text.strip() not in _JSON_CLOSING_LINES:
            owner = next((p for _, k, p in reversed(stack) if k == "package"), None)
            if owner is not None:
                changes.mark(owner)
    return changes.result()


# A requirement, as pip reads it: a name, optional extras, then either
# version clauses or "@ url", then an optional marker, comment, line
# continuation or per-requirement option such as --hash.
_REQUIREMENT_NAME_RE = re.compile(
    r"([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*"
)
_REQUIREMENT_CLAUSE_RE = re.compile(r"(===|==|~=|!=|<=|>=|<|>)\s*([^\s,;#\\()]+)\s*")
_REQUIREMENT_END_RE = re.compile(r";|#|\\|--|$")
_STARTS_WITH_NAME_RE = re.compile(r"[A-Za-z0-9]")
_MAX_SHOWN_LINE = 120


def _parse_requirement(line: str) -> tuple[str, str] | None:
    """Read one requirements line as ``(name, version)``, or None if it is not one.

    Only a single ``==`` clause without a wildcard yields a version. For a
    bare name, a range or ``name @ url`` there is nothing to check the
    installed version against, so the version is empty and whatever is
    installed gets scanned.
    """
    m = _REQUIREMENT_NAME_RE.match(line)
    if not m:
        return None
    name, rest = m.group(1).lower(), line[m.end() :]
    if rest.startswith("@"):
        return name, ""

    parenthesised = rest.startswith("(")
    if parenthesised:
        rest = rest[1:].lstrip()
    clauses: list[tuple[str, str]] = []
    while True:
        clause = _REQUIREMENT_CLAUSE_RE.match(rest)
        if not clause:
            break
        clauses.append((clause.group(1), clause.group(2)))
        rest = rest[clause.end() :]
        if not rest.startswith(","):
            break
        rest = rest[1:].lstrip()
    if parenthesised:
        if not rest.startswith(")"):
            return None
        rest = rest[1:].lstrip()
    if not _REQUIREMENT_END_RE.match(rest):
        return None

    version = ""
    if len(clauses) == 1 and clauses[0][0] in ("==", "===") and "*" not in clauses[0][1]:
        version = clauses[0][1]
    return name, version


# "-e" in front of a URL or path installs it in editable mode.
_EDITABLE_RE = re.compile(r"(?:-e|--editable)(?:\s+|=)")
# The name pip gives a project installed from a URL: "...#egg=name".
_EGG_RE = re.compile(r"[#&]egg=([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(?=$|[&\[])")
_SDIST_SUFFIXES = (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip")
_PATH_SEPARATOR_RE = re.compile(r"[/\\]")
_PATH_STARTS = (".", "/", "~")


def _split_reference(text: str) -> tuple[str, bool]:
    """Split a URL or path line into the URL or path and whether the rest is well formed."""
    target, _, rest = text.partition(" ")
    return target, _REQUIREMENT_END_RE.match(rest.lstrip()) is not None


def _parse_reference(text: str) -> tuple[str, str] | None:
    """Read a URL or path requirement as ``(name, version)``, or None if it names no package.

    The name comes from an ``#egg=`` fragment, or from the file name of a
    wheel or source archive, which gives the version as well. A URL or path
    with neither does not say what it installs.
    """
    target, well_formed = _split_reference(text)
    if not well_formed:
        return None
    egg = _EGG_RE.search(target)
    if egg:
        return egg.group(1).lower(), ""
    location = re.split(r"[#?]", target, maxsplit=1)[0]
    filename = _PATH_SEPARATOR_RE.split(location)[-1]
    if filename.lower().endswith(".whl"):
        # name-version-python-abi-platform, with an optional build tag after the version
        fields = filename[: -len(".whl")].split("-")
        return (fields[0].lower(), fields[1]) if len(fields) in (5, 6) else None
    for suffix in _SDIST_SUFFIXES:
        if filename.lower().endswith(suffix):
            name, dash, version = filename[: -len(suffix)].rpartition("-")
            return (name.lower(), version) if dash and name and version else None
    return None


def _is_project_directory(text: str) -> bool:
    """True for a relative path that stays inside the project: ``.``, ``./tools/plugin``.

    That is the project's own code, which the scan of the source covers.
    """
    target, well_formed = _split_reference(text)
    if not well_formed or "://" in target or not target.startswith("."):
        return False
    if target.lower().endswith((".whl", *_SDIST_SUFFIXES)):
        return False  # an archive, whatever its name: something is installed from it
    return ".." not in _PATH_SEPARATOR_RE.split(target)


def _parse_pip_diff(diff_text: str, problems: list[str] | None = None) -> list[tuple[str, str]]:
    """Parse a requirements.txt diff for added packages.

    Comments, blank lines and options such as ``-r`` and ``--hash`` are
    passed over, and so is a directory inside the project (``-e .``). A
    URL or a path is read for the package it names. Any other added line,
    one that cannot be read as a requirement or a URL or path that names no
    package, is described in *problems*: it may install something that is
    then never scanned.
    """
    packages: list[tuple[str, str]] = []
    for line in diff_text.splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        added = line[1:].strip()
        editable = _EDITABLE_RE.match(added)
        text = added[editable.end() :].strip() if editable else added
        if (
            not editable
            and not _STARTS_WITH_NAME_RE.match(text)
            and not text.startswith(_PATH_STARTS)
        ):
            continue
        is_reference = (
            bool(editable) or "://" in text.split(" ")[0] or text.startswith(_PATH_STARTS)
        )

        requirement = None if editable else _parse_requirement(text)
        if requirement is None:
            requirement = _parse_reference(text)
        if requirement is not None:
            packages.append(requirement)
        elif is_reference and _is_project_directory(text):
            continue
        elif problems is not None:
            shown = spell_out(added[:_MAX_SHOWN_LINE])
            if len(added) > _MAX_SHOWN_LINE:
                shown += "..."
            reason = (
                "does not say which package it installs"
                if is_reference
                else "could not be read as a requirement"
            )
            problems.append(f'the added line "{shown}" {reason}')
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

# What another interpreter is asked: where it keeps installed packages. The
# first statement takes the working directory off its import path. "python -c"
# puts that directory first, and the interpreter starts in the tree being
# checked, so a sysconfig.py committed there is what "import sysconfig" would
# otherwise run. sys is built in and is not looked up on the path at all.
_SITE_PACKAGES_QUERY = (
    "import sys; sys.path[:] = [p for p in sys.path if p]; "
    "import site, sysconfig; p = sysconfig.get_paths(); "
    "print(p['purelib']); print(p['platlib']); "
    "print(site.getusersitepackages() if site.ENABLE_USER_SITE else '')"
)


def _node_installed_version(pkg_dir: Path) -> str | None:
    try:
        data = json.loads((pkg_dir / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    version = cast("dict[str, object]", data).get("version")
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
def _path_site_packages() -> tuple[tuple[Path, ...], ...]:
    """Site-packages of the other Python interpreters on PATH, one group for each.

    Under pre-commit heckler runs from its own isolated environment, which
    never holds the project's dependencies. pre-commit puts that environment
    first on PATH and leaves the rest as it was, so a virtualenv that was
    active when the commit started is still there to be found.
    """
    own_bin = os.path.dirname(os.path.abspath(sys.executable))
    names = ("python.exe",) if os.name == "nt" else ("python3", "python")
    found: list[tuple[Path, ...]] = []
    queried = 0
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory or os.path.abspath(directory) == own_bin:
            continue
        for name in names:
            executable = os.path.join(directory, name)
            if os.path.isfile(executable) and os.access(executable, os.X_OK):
                found.append(tuple(_query_interpreter(executable)))
                queried += 1
                break
        if queried >= _MAX_PATH_INTERPRETERS:
            break
    return tuple(found)


def _python_environments(lockfile_dir: Path) -> Iterator[list[Path]]:
    """Python environments that may hold the project's dependencies.

    Each is given as its site-packages directories, of which one interpreter
    can have three: for pure Python, for compiled code and for the user. A
    package is free to install into any of them, so they are searched as one
    place. A directory is listed once, in the first environment that has it.

    Cheapest and most specific first: a virtualenv next to the lockfile or in
    the working directory, then the environment heckler itself runs in, then
    whatever other interpreters are on PATH.
    """
    seen: set[Path] = set()

    def fresh(paths: Iterable[Path]) -> list[Path]:
        new: list[Path] = []
        for path in paths:
            resolved = path.resolve()
            if resolved not in seen and path.is_dir():
                seen.add(resolved)
                new.append(path)
        return new

    for base in (lockfile_dir, Path.cwd()):
        for name in _VENV_DIR_NAMES:
            venv = base / name
            if (venv / "pyvenv.cfg").is_file():
                yield fresh(_venv_site_packages(venv))
    yield fresh(_own_site_packages())
    for interpreter in _path_site_packages():
        yield fresh(interpreter)


def _normalize_dist_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# A version in every spelling PEP 440 allows: "1.0alpha1", "1.0-a.1" and
# "1.0A1" are one version, and so are "1.0.post1" and "1.0-1". This is the
# pattern from the appendix of the PEP. tests/test_requirements_oracle.py
# holds it to what the packaging library, the reference implementation,
# says about the same strings.
_PEP440_RE = re.compile(
    r"""
    v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?:[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?P<post>-(?P<post_n1>[0-9]+)|[-_.]?(?:post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?)?
    (?P<dev>[-_.]?dev[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?
    """,
    re.VERBOSE | re.IGNORECASE,
)
_PRE_RELEASE_LETTERS = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}


def _version_key(version: str) -> tuple[object, ...] | None:
    """What two spellings of one version have in common; None if it is not a PEP 440 version."""
    m = _PEP440_RE.fullmatch(version.strip())
    if not m:
        return None
    release = [int(part) for part in m.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre = None
    if m.group("pre_l"):
        letter = m.group("pre_l").lower()
        pre = (_PRE_RELEASE_LETTERS.get(letter, letter), int(m.group("pre_n") or 0))
    post = int(m.group("post_n1") or m.group("post_n2") or 0) if m.group("post") else None
    dev = int(m.group("dev_n") or 0) if m.group("dev") else None
    return int(m.group("epoch") or 0), tuple(release), pre, post, dev


def _same_python_version(left: str, right: str) -> bool:
    """Compare two version strings the way ``==`` does.

    The local part (``+cpu``) is not compared: a pin seldom carries one,
    and the installed copy of what it names often does.
    """
    left_key, right_key = _version_key(left), _version_key(right)
    if left_key is None or right_key is None:
        # Not versions as PEP 440 knows them. Then only the same text is
        # the same version.
        return left.strip().lower() == right.strip().lower()
    return left_key == right_key


class _Installed(NamedTuple):
    """A ``.dist-info`` or ``.egg-info`` directory, and what it says it is."""

    metadata: Path
    names: frozenset[str]  # normalised
    versions: tuple[str, ...]

    def is_version(self, version: str) -> bool:
        """Whether this may be *version*; an entry that gives none cannot be checked."""
        return not self.versions or any(_same_python_version(v, version) for v in self.versions)


def _declared(metadata: Path) -> tuple[list[str], list[str]]:
    """Every ``Name`` and ``Version`` header in the metadata file of an entry.

    Read more generously than an installer reads them: a header counts
    wherever it stands before the first empty line, and all of them count
    when there are several. An entry taken for a package it is not costs a
    scan; one that is missed can hide what it installed.
    """
    names: list[str] = []
    versions: list[str] = []
    headers = {"name": names, "version": versions}
    for filename in ("METADATA", "PKG-INFO"):
        try:
            with open(metadata / filename, encoding="utf-8", errors="replace") as f:
                values: list[str] | None = None
                for line in f:
                    if line == "\n":
                        break
                    if line[0] in " \t":
                        if values is not None:
                            values[-1] += line  # a value folded over several lines
                        continue
                    key, _, value = line.partition(":")
                    values = headers.get(key.strip().lower())
                    if values is not None:
                        values.append(value)
        except OSError:
            continue
    return [name.strip() for name in names], [version.strip() for version in versions]


@functools.cache
def _installed_distributions(site_packages: Path) -> tuple[_Installed, ...]:
    """The distributions that left metadata in a site-packages directory.

    Read once for a scan, however many packages changed: the callers that
    start one, scan_changed_deps() and resolve_package(), forget it first.

    A distribution goes by the name in its directory name and by the one in
    its metadata file, and likewise for the version. Neither is taken over
    the other, because an installer does not hold them to each other: pip
    checks the metadata file against what was asked for, and of the
    directory name only that it starts with the project name.

    Only a directory counts. A file with one of the suffixes lists nothing
    that was installed, so it cannot speak for a package.
    """
    try:
        entries = sorted(site_packages.iterdir())
    except OSError:
        return ()
    found: list[_Installed] = []
    for entry in entries:
        if entry.suffix not in (".dist-info", ".egg-info") or not entry.is_dir():
            continue
        parts = entry.name[: -len(entry.suffix)].split("-")
        names, versions = _declared(entry)
        names.append(parts[0])
        versions[:0] = parts[1:2]
        found.append(
            _Installed(
                entry,
                frozenset(_normalize_dist_name(name) for name in names if name),
                tuple(dict.fromkeys(version for version in versions if version)),
            )
        )
    return tuple(found)


def _find_distributions(site_packages: Path, name: str) -> list[_Installed]:
    """Every installed distribution that goes by *name*.

    The import name of a package is often not its distribution name (PyYAML
    installs ``yaml``), so the lookup goes through the ``.dist-info`` and
    ``.egg-info`` directories that installers leave behind.
    """
    wanted = _normalize_dist_name(name)
    return [dist for dist in _installed_distributions(site_packages) if wanted in dist.names]


def _distribution_files(
    site_packages: Path, metadata: Path, all_text: bool = False
) -> list[Path] | None:
    """What a distribution installed that is worth scanning.

    ``RECORD`` lists every installed file, which keeps the scan to this one
    distribution even when it shares a namespace directory with others.
    Without it, ``top_level.txt`` names the modules and packages.

    None when the metadata does not lead to a single installed file: there
    is no list, the list cannot be read, or nothing on it exists as a file,
    a package directory or a ``.py`` module. That is not the empty list,
    which is a distribution that installed files and none worth scanning.

    With *all_text* (``--all-text``) every listed file is returned, not only
    those with a source extension. Which of them is binary is left to the
    scanner, which reads a file in full before it says so and records the
    ones it leaves out.
    """
    record = metadata / "RECORD"
    if record.is_file():
        try:
            with open(record, encoding="utf-8", newline="") as f:
                rows = [row for row in csv.reader(f) if row]
        except (OSError, UnicodeDecodeError, csv.Error):
            return None
        files: list[Path] = []
        installed = False
        for row in rows:
            relative = PurePosixPath(row[0])
            if relative.is_absolute() or ".." in relative.parts:
                continue  # scripts and data installed outside site-packages
            path = site_packages.joinpath(*relative.parts)
            if not path.is_file():
                continue
            installed = True
            if all_text or Scanner.is_dependency_source(path):
                files.append(path)
        return files if installed else None

    targets: list[Path] = []
    top_level = metadata / "top_level.txt"
    if top_level.is_file():
        try:
            modules = top_level.read_text(encoding="utf-8").split()
        except (OSError, UnicodeDecodeError):
            modules = []
        for module in modules:
            if module in (".", "..") or "/" in module or "\\" in module:
                continue  # a path, which would lead out of what was installed
            if (site_packages / module).is_dir():
                targets.append(site_packages / module)
            elif (site_packages / f"{module}.py").is_file():
                targets.append(site_packages / f"{module}.py")
    return targets or None


def _resolve_python(
    pkg_name: str, version: str, lockfile_dir: Path, all_text: bool = False
) -> tuple[list[Path], str]:
    other_versions: list[str] = []
    for directories in _python_environments(lockfile_dir):
        found = [
            (site_packages, dist)
            for site_packages in directories
            for dist in _find_distributions(site_packages, pkg_name)
        ]
        if not found:
            continue
        if version and not any(dist.is_version(version) for _, dist in found):
            other_versions.extend(dist.versions[0] for _, dist in found)
            continue

        # An environment should hold one distribution of a name. When it
        # holds more, which of them describes the code that gets imported is
        # not something their names settle, and a package can install an
        # entry made to be found first. So none is chosen over another:
        # what any of them lists is scanned, whatever version it gives. One
        # that lists nothing takes nothing from the rest; the package goes
        # unscanned only when none of them leads to a file.
        targets: dict[Path, None] = {}
        unlisted: list[str] = []
        for site_packages, dist in found:
            files = _distribution_files(site_packages, dist.metadata, all_text)
            if files is None:
                unlisted.append(dist.metadata.name)
            else:
                targets.update(dict.fromkeys(files))
        if len(unlisted) == len(found):
            one = len(unlisted) == 1
            return [], (
                f"{' and '.join(unlisted)} {'does' if one else 'do'} not say which"
                f" files {'it' if one else 'they'} installed"
            )
        return list(targets), ""
    if other_versions:
        return [], f"the installed version is {other_versions[0]}"

    # No installer metadata anywhere: fall back to a directory named after
    # the package, which is all that can be said about such an install.
    for directories in _python_environments(lockfile_dir):
        for site_packages in directories:
            for guess in (pkg_name, pkg_name.replace("-", "_")):
                if (site_packages / guess).is_dir():
                    return [site_packages / guess], ""
    return [], "it is not installed"


def resolve_package(
    pkg_name: str, version: str, ecosystem: str, lockfile_path: str, all_text: bool = False
) -> tuple[list[Path], str]:
    """Find what to scan for a package that changed in a lockfile.

    Returns ``(targets, problem)``. *targets* are directories or files to
    scan and may be empty for a package that ships nothing scannable.
    *problem* is empty on success; otherwise it says why the package cannot
    be scanned, which is the case when it is not installed, when the
    installed copy is a different version than the lockfile names, or when
    a Python package's metadata leads to none of the files it installed.

    A Python package is every distribution of that name in the environment
    it was found in. Where there is more than one, what each of them lists
    is scanned.

    *all_text* is ``--all-text``: return every file a Python distribution
    installed, rather than the ones with a source extension. Scan those with
    ``Scanner.scan_path(target, by_content=True)``, which leaves out the
    binary ones as a directory walk does. Directories are filtered by the
    scanner either way.
    """
    _installed_distributions.cache_clear()  # what is installed now, not at the last call
    return _locate_package(pkg_name, version, ecosystem, lockfile_path, all_text)


def _locate_package(
    pkg_name: str, version: str, ecosystem: str, lockfile_path: str, all_text: bool
) -> tuple[list[Path], str]:
    lockfile_dir = Path(lockfile_path).parent
    if ecosystem in _NODE_ECOSYSTEMS:
        return _resolve_node(pkg_name, version, ecosystem, lockfile_dir)
    if ecosystem in _PYTHON_ECOSYSTEMS:
        return _resolve_python(pkg_name, version, lockfile_dir, all_text)
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

    Anything that could not be checked is reported on stderr and, when
    *unscanned* is given, described there so the caller can fail the run: a
    lockfile heckler has no parser for, a part of one it could not read, and
    a changed package that is missing, installed at another version, or
    described by metadata that lists none of its installed files.
    """
    all_findings: list[Finding] = []
    all_text = scanner.all_text
    _installed_distributions.cache_clear()

    def not_scanned(message: str) -> None:
        print(f"Warning: {message}", file=sys.stderr)
        if unscanned is not None:
            unscanned.append(message)

    for lf_path in lockfile_paths:
        ecosystem = detect_ecosystem(lf_path)
        if ecosystem == "unknown":
            not_scanned(f"{lf_path} was not scanned: it is not a lockfile heckler can read")
            continue
        if ecosystem in _UNPARSED_ECOSYSTEMS:
            not_scanned(f"{lf_path} was not scanned: {ecosystem} lockfiles are not supported yet")
            continue

        diff_text = get_lockfile_diff(lf_path)
        if not diff_text:
            print(f"Warning: No diff available for {lf_path}. Skipping.", file=sys.stderr)
            continue

        problems: list[str] = []
        packages = parse_changed_packages(diff_text, ecosystem, problems)
        for problem in problems:
            not_scanned(f"{lf_path}: {problem}")

        for pkg_name, version in packages:
            targets, problem = _locate_package(pkg_name, version, ecosystem, lf_path, all_text)
            if problem:
                label = f"{pkg_name} {version}".strip()
                not_scanned(f"{label} changed in {lf_path} but was not scanned: {problem}")
                continue
            # Two distributions of one name can list the same file, or one a
            # directory and the other a file in it; a finding is reported once.
            reported: set[tuple[str, int, int, int, str]] = set()
            for target in targets:
                # With --all-text a target can be any file the package
                # installed, compiled ones included. The scanner leaves out
                # the binary ones, as it does in a directory walk.
                for f in scanner.scan_path(target, by_content=all_text):
                    key = (f.file, f.line, f.column, f.codepoint, f.char_name)
                    if key in reported:
                        continue
                    reported.add(key)
                    # Tag findings with package info
                    f.source = "dependency"
                    f.package = pkg_name
                    all_findings.append(f)

    return all_findings
