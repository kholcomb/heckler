"""Tests for lockfile diff parsing."""

from __future__ import annotations

import copy
import difflib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from heckler.lockfile import (
    detect_ecosystem,
    get_lockfile_diff,
    parse_changed_packages,
    resolve_package_dir,
    scan_changed_deps,
)
from heckler.scanner import Scanner


class TestDetectEcosystem:
    def test_npm(self) -> None:
        assert detect_ecosystem("package-lock.json") == "npm"

    def test_yarn(self) -> None:
        assert detect_ecosystem("yarn.lock") == "yarn"

    def test_pnpm(self) -> None:
        assert detect_ecosystem("pnpm-lock.yaml") == "pnpm"

    def test_pip(self) -> None:
        assert detect_ecosystem("requirements.txt") == "pip"

    def test_poetry(self) -> None:
        assert detect_ecosystem("poetry.lock") == "poetry"

    def test_unknown(self) -> None:
        assert detect_ecosystem("somefile.txt") == "unknown"

    def test_full_path(self) -> None:
        assert detect_ecosystem("/path/to/package-lock.json") == "npm"


class TestParseChangedPackages:
    def test_npm_lockfile_diff(self) -> None:
        diff = """\
--- a/package-lock.json
+++ b/package-lock.json
@@ -1,5 +1,10 @@
+    "node_modules/lodash": {
+      "version": "4.17.21"
+    },
+    "node_modules/@scope/pkg": {
+      "version": "1.0.0"
     }
"""
        packages = parse_changed_packages(diff, "npm")
        names = [p[0] for p in packages]
        assert "lodash" in names
        assert "@scope/pkg" in names

    def test_pip_diff(self) -> None:
        diff = """\
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,3 +1,5 @@
 flask==3.0.0
+requests==2.31.0
+django>=4.2
"""
        packages = parse_changed_packages(diff, "pip")
        names = [p[0] for p in packages]
        assert "requests" in names
        assert "django" in names

    def test_yarn_diff(self) -> None:
        diff = """\
--- a/yarn.lock
+++ b/yarn.lock
@@ -1,5 +1,10 @@
+"lodash@^4.17.21":
+  version "4.17.21"
+"@babel/core@^7.24.0":
+  version "7.24.0"
"""
        packages = parse_changed_packages(diff, "yarn")
        names = [p[0] for p in packages]
        assert "lodash" in names
        assert "@babel/core" in names

    def test_pnpm_diff(self) -> None:
        diff = """\
--- a/pnpm-lock.yaml
+++ b/pnpm-lock.yaml
@@ -1,5 +1,10 @@
+  /lodash@4.17.21:
+    resolution: {integrity: sha512-xxx}
+  /@scope/pkg@1.0.0:
+    resolution: {integrity: sha512-yyy}
"""
        packages = parse_changed_packages(diff, "pnpm")
        names = [p[0] for p in packages]
        assert "lodash" in names
        assert "@scope/pkg" in names

    def test_empty_diff(self) -> None:
        assert parse_changed_packages("", "npm") == []


# ---------------------------------------------------------------------------
# Integration tests using the real project git repo
# All operations are non-destructive: we create new temp files, stage them,
# test, then always unstage + delete in a finally block.
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent


def _git(*args: str, cwd: Path = REPO_ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        timeout=10,
        cwd=cwd,
    )


def _is_git_repo() -> bool:
    return _git("rev-parse", "--git-dir").returncode == 0


@pytest.mark.skipif(not _is_git_repo(), reason="Not a git repository")
class TestGetLockfileDiffIntegration:
    """Test get_lockfile_diff() against the real project git repo.

    Creates a temp package-lock.json, stages it, reads the diff, then cleans up.
    Non-destructive: only creates/removes a new file, never modifies existing ones.
    """

    TEMP_LOCKFILE = REPO_ROOT / "_test_package-lock.json"

    def _cleanup(self) -> None:
        """Unstage and remove the temp lockfile. Safe to call even if file doesn't exist."""
        _git("restore", "--staged", "--", str(self.TEMP_LOCKFILE))
        self.TEMP_LOCKFILE.unlink(missing_ok=True)

    def test_staged_diff_returns_content(self) -> None:
        try:
            # Create a new lockfile with a known package
            lockfile_content = json.dumps(
                {
                    "name": "test",
                    "lockfileVersion": 3,
                    "packages": {
                        "node_modules/heckler-test-pkg": {
                            "version": "1.0.0",
                        }
                    },
                },
                indent=2,
            )
            self.TEMP_LOCKFILE.write_text(lockfile_content, encoding="utf-8")
            _git("add", "--", str(self.TEMP_LOCKFILE))

            # get_lockfile_diff should return the staged diff
            diff = get_lockfile_diff(str(self.TEMP_LOCKFILE))
            assert diff, "Expected non-empty diff for newly staged file"
            assert "heckler-test-pkg" in diff
            assert "node_modules/heckler-test-pkg" in diff
        finally:
            self._cleanup()

    def test_parse_staged_diff_extracts_packages(self) -> None:
        try:
            lockfile_content = json.dumps(
                {
                    "name": "test",
                    "lockfileVersion": 3,
                    "packages": {
                        "node_modules/lodash": {"version": "4.17.21"},
                        "node_modules/@scope/evil-pkg": {"version": "0.0.1"},
                    },
                },
                indent=2,
            )
            self.TEMP_LOCKFILE.write_text(lockfile_content, encoding="utf-8")
            _git("add", "--", str(self.TEMP_LOCKFILE))

            diff = get_lockfile_diff(str(self.TEMP_LOCKFILE))
            packages = parse_changed_packages(diff, "npm")
            names = [p[0] for p in packages]
            assert "lodash" in names
            assert "@scope/evil-pkg" in names
        finally:
            self._cleanup()


@pytest.mark.skipif(not _is_git_repo(), reason="Not a git repository")
class TestResolvePackageDirIntegration:
    """Test resolve_package_dir() with real directory structures.

    Creates temp node_modules dirs, tests resolution, then cleans up.
    """

    TEMP_NM = REPO_ROOT / "_test_node_modules"

    def _cleanup(self) -> None:
        if self.TEMP_NM.exists():
            shutil.rmtree(self.TEMP_NM)

    def test_resolves_unscoped_package(self) -> None:
        try:
            pkg_dir = self.TEMP_NM / "lodash"
            pkg_dir.mkdir(parents=True)
            (pkg_dir / "index.js").write_text("module.exports = {};", encoding="utf-8")

            # resolve_package_dir looks for node_modules relative to the lockfile
            # We need a fake lockfile path whose parent contains our _test_node_modules
            # Rename temporarily to node_modules for the test
            real_nm = REPO_ROOT / "node_modules"
            if not real_nm.exists():
                self.TEMP_NM.rename(real_nm)
                result = resolve_package_dir("lodash", "npm", str(REPO_ROOT / "package-lock.json"))
                assert result is not None
                assert result.name == "lodash"
                # Rename back
                real_nm.rename(self.TEMP_NM)
            else:
                pytest.skip("node_modules already exists in repo root")
        finally:
            self._cleanup()

    def test_resolves_scoped_package(self) -> None:
        try:
            pkg_dir = self.TEMP_NM / "@scope" / "pkg"
            pkg_dir.mkdir(parents=True)
            (pkg_dir / "index.js").write_text("module.exports = {};", encoding="utf-8")

            real_nm = REPO_ROOT / "node_modules"
            if not real_nm.exists():
                self.TEMP_NM.rename(real_nm)
                lockfile = str(REPO_ROOT / "package-lock.json")
                result = resolve_package_dir("@scope/pkg", "npm", lockfile)
                assert result is not None
                assert result.name == "pkg"
                real_nm.rename(self.TEMP_NM)
            else:
                pytest.skip("node_modules already exists in repo root")
        finally:
            self._cleanup()

    def test_returns_none_for_missing_package(self) -> None:
        lockfile = str(REPO_ROOT / "package-lock.json")
        result = resolve_package_dir("nonexistent-pkg-xyz", "npm", lockfile)
        assert result is None


@pytest.mark.skipif(not _is_git_repo(), reason="Not a git repository")
class TestScanChangedDepsIntegration:
    """End-to-end: stage a lockfile referencing a package with planted invisible
    Unicode, then verify scan_changed_deps() finds it.

    Creates temp lockfile + node_modules with a planted Glassworm signature.
    All cleaned up in finally blocks.
    """

    # Use a subdirectory so the lockfile has the canonical name
    TEMP_DIR = REPO_ROOT / "_test_integration"
    TEMP_LOCKFILE = TEMP_DIR / "package-lock.json"
    TEMP_NM = TEMP_DIR / "node_modules"

    def _cleanup(self) -> None:
        _git("restore", "--staged", "--", str(self.TEMP_LOCKFILE))
        if self.TEMP_DIR.exists():
            shutil.rmtree(self.TEMP_DIR)

    def test_full_chain_detects_planted_chars(self) -> None:
        try:
            # 1. Create node_modules with a malicious package
            evil_dir = self.TEMP_NM / "evil-pkg"
            evil_dir.mkdir(parents=True)
            (evil_dir / "index.js").write_text(
                "const payload = `\ufe00\ufe01\ufe0f`;\n",
                encoding="utf-8",
            )

            # 2. Create and stage a lockfile referencing it
            lockfile_content = json.dumps(
                {
                    "name": "test",
                    "lockfileVersion": 3,
                    "packages": {
                        "node_modules/evil-pkg": {"version": "1.0.0"},
                    },
                },
                indent=2,
            )
            self.TEMP_LOCKFILE.write_text(lockfile_content, encoding="utf-8")
            _git("add", "--", str(self.TEMP_LOCKFILE))

            # 3. Run the full scan_changed_deps chain
            scanner = Scanner(scan_deps=True)
            findings = scan_changed_deps([str(self.TEMP_LOCKFILE)], scanner)

            # 4. Verify: should find the planted variation selectors
            assert len(findings) >= 3, f"Expected >=3 findings, got {len(findings)}"
            assert all(f.source == "dependency" for f in findings)
            assert all(f.package == "evil-pkg" for f in findings)
            assert any("Variation Selector" in f.char_name for f in findings)

        finally:
            self._cleanup()


# ---------------------------------------------------------------------------
# Version bumps: the package name is an unchanged line, only the lines below
# it change. Diffs are built from before/after lockfiles with full context,
# which is what get_lockfile_diff() asks git for.
# ---------------------------------------------------------------------------


def _full_diff(old: str, new: str) -> str:
    return "\n".join(
        difflib.unified_diff(
            old.splitlines(),
            new.splitlines(),
            "a/lock",
            "b/lock",
            n=1_000_000,
            lineterm="",
        )
    )


_NPM_LOCK: dict[str, object] = {
    "name": "demo",
    "lockfileVersion": 2,
    "packages": {
        "": {"name": "demo", "dependencies": {"express": "^4.18.0"}},
        "node_modules/@scope/pkg": {"version": "1.0.0", "integrity": "sha512-SSSS"},
        "node_modules/accepts": {"version": "1.3.8", "integrity": "sha512-AAAA"},
        "node_modules/express": {
            "version": "4.18.0",
            "resolved": "https://registry.npmjs.org/express/-/express-4.18.0.tgz",
            "integrity": "sha512-EEEE",
            "dependencies": {"accepts": "~1.3.8"},
        },
        "node_modules/express/node_modules/debug": {"version": "2.6.9"},
    },
    "dependencies": {
        "express": {"version": "4.18.0", "requires": {"accepts": "~1.3.8"}},
    },
}


def _npm_diff(mutate: object) -> str:
    new = copy.deepcopy(_NPM_LOCK)
    mutate(new)  # type: ignore[operator]
    return _full_diff(json.dumps(_NPM_LOCK, indent=2), json.dumps(new, indent=2))


class TestNpmVersionBumps:
    def test_bump_of_existing_package(self) -> None:
        def bump(lock: dict) -> None:  # type: ignore[type-arg]
            entry = lock["packages"]["node_modules/express"]
            entry["version"] = "4.18.2"
            entry["resolved"] = "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
            entry["integrity"] = "sha512-FFFF"

        assert parse_changed_packages(_npm_diff(bump), "npm") == [("express", "4.18.2")]

    def test_change_deep_inside_a_block(self) -> None:
        def bump(lock: dict) -> None:  # type: ignore[type-arg]
            lock["packages"]["node_modules/express"]["dependencies"]["accepts"] = "~1.3.9"

        assert parse_changed_packages(_npm_diff(bump), "npm") == [("express", "4.18.0")]

    def test_bump_of_nested_package(self) -> None:
        def bump(lock: dict) -> None:  # type: ignore[type-arg]
            lock["packages"]["node_modules/express/node_modules/debug"]["version"] = "2.6.10"

        assert parse_changed_packages(_npm_diff(bump), "npm") == [
            ("express/node_modules/debug", "2.6.10"),
        ]

    def test_new_package_reports_only_itself(self) -> None:
        def add(lock: dict) -> None:  # type: ignore[type-arg]
            lock["packages"]["node_modules/zebra"] = {"version": "1.0.0"}

        assert parse_changed_packages(_npm_diff(add), "npm") == [("zebra", "1.0.0")]

    def test_root_entry_change_is_not_a_package(self) -> None:
        def edit(lock: dict) -> None:  # type: ignore[type-arg]
            lock["packages"][""]["dependencies"]["express"] = "^4.18.2"

        assert parse_changed_packages(_npm_diff(edit), "npm") == []

    def test_removed_package_does_not_implicate_its_neighbour(self) -> None:
        def remove(lock: dict) -> None:  # type: ignore[type-arg]
            del lock["packages"]["node_modules/accepts"]

        assert parse_changed_packages(_npm_diff(remove), "npm") == []

    def test_legacy_dependencies_section_is_not_the_last_package(self) -> None:
        def edit(lock: dict) -> None:  # type: ignore[type-arg]
            lock["dependencies"]["express"]["version"] = "4.18.2"

        assert parse_changed_packages(_npm_diff(edit), "npm") == []


_YARN_CLASSIC = """\
# yarn lockfile v1


"@babel/core@^7.24.0":
  version "7.24.0"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.24.0.tgz#abc"
  integrity sha512-AAAA
  dependencies:
    "@babel/helper" "^7.24.0"

lodash@^4.17.0, lodash@^4.17.20:
  version "4.17.20"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz#def"
  integrity sha512-BBBB
"""

_YARN_BERRY = """\
__metadata:
  version: 8
  cacheKey: 10c0

"demo@workspace:.":
  version: 0.0.0-use.local
  resolution: "demo@workspace:."
  dependencies:
    lodash: "npm:^4.17.20"
  languageName: unknown
  linkType: soft

"lodash@npm:^4.17.20, lodash@npm:^4.17.21":
  version: 4.17.20
  resolution: "lodash@npm:4.17.20"
  checksum: 10c0/aaaa
  languageName: node
  linkType: hard
"""


class TestYarnVersionBumps:
    def test_classic_bump(self) -> None:
        new = _YARN_CLASSIC.replace("4.17.20", "4.17.21").replace("BBBB", "CCCC")
        # The range in the header also reads 4.17.20; keep the header unchanged.
        new = new.replace("lodash@^4.17.21:", "lodash@^4.17.20:")
        assert parse_changed_packages(_full_diff(_YARN_CLASSIC, new), "yarn") == [
            ("lodash", "4.17.21"),
        ]

    def test_classic_scoped_bump(self) -> None:
        new = _YARN_CLASSIC.replace('version "7.24.0"', 'version "7.24.1"')
        assert parse_changed_packages(_full_diff(_YARN_CLASSIC, new), "yarn") == [
            ("@babel/core", "7.24.1"),
        ]

    def test_berry_bump(self) -> None:
        new = _YARN_BERRY.replace("version: 4.17.20", "version: 4.17.21")
        new = new.replace("lodash@npm:4.17.20", "lodash@npm:4.17.21")
        assert parse_changed_packages(_full_diff(_YARN_BERRY, new), "yarn") == [
            ("lodash", "4.17.21"),
        ]

    def test_berry_workspace_and_metadata_are_not_packages(self) -> None:
        new = _YARN_BERRY.replace('lodash: "npm:^4.17.20"', 'lodash: "npm:^4.17.21"')
        new = new.replace("cacheKey: 10c0", "cacheKey: 10c1")
        assert parse_changed_packages(_full_diff(_YARN_BERRY, new), "yarn") == []

    def test_alias_resolves_to_installed_name(self) -> None:
        new = _YARN_CLASSIC + '\n"foo@npm:bar@^1.0.0":\n  version "1.0.0"\n'
        assert parse_changed_packages(_full_diff(_YARN_CLASSIC, new), "yarn") == [
            ("foo", "1.0.0"),
        ]


_POETRY_LOCK = """\
[[package]]
name = "certifi"
version = "2024.2.2"
description = "Mozilla's CA bundle"
optional = false
python-versions = ">=3.6"
files = [
    {file = "certifi-2024.2.2-py3-none-any.whl", hash = "sha256:aaaa"},
]

[[package]]
name = "Requests"
version = "2.31.0"
description = "HTTP for Humans"
optional = false
python-versions = ">=3.7"
files = [
    {file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:bbbb"},
]

[package.dependencies]
certifi = ">=2017.4.17"

[package.extras]
socks = ["PySocks (>=1.5.6,!=1.5.7)"]

[metadata]
lock-version = "2.0"
python-versions = "^3.9"
content-hash = "cccc"
"""


class TestPoetryVersionBumps:
    def test_bump(self) -> None:
        new = _POETRY_LOCK.replace("2.31.0", "2.32.0").replace("bbbb", "dddd")
        assert parse_changed_packages(_full_diff(_POETRY_LOCK, new), "poetry") == [
            ("requests", "2.32.0"),
        ]

    def test_sub_table_change_belongs_to_its_package(self) -> None:
        new = _POETRY_LOCK.replace('certifi = ">=2017.4.17"', 'certifi = ">=2023.5.7"')
        assert parse_changed_packages(_full_diff(_POETRY_LOCK, new), "poetry") == [
            ("requests", "2.31.0"),
        ]

    def test_metadata_change_is_not_a_package(self) -> None:
        new = _POETRY_LOCK.replace('content-hash = "cccc"', 'content-hash = "eeee"')
        assert parse_changed_packages(_full_diff(_POETRY_LOCK, new), "poetry") == []

    def test_new_package(self) -> None:
        new = _POETRY_LOCK.replace(
            "[metadata]",
            '[[package]]\nname = "idna"\nversion = "3.7"\n\n[metadata]',
        )
        assert parse_changed_packages(_full_diff(_POETRY_LOCK, new), "poetry") == [
            ("idna", "3.7"),
        ]


class TestNpmEntryKinds:
    def test_workspace_link_is_not_a_dependency(self) -> None:
        def add(lock: dict) -> None:  # type: ignore[type-arg]
            lock["packages"]["node_modules/app"] = {"resolved": "packages/app", "link": True}

        assert parse_changed_packages(_npm_diff(add), "npm") == []

    def test_dependency_named_version_is_not_the_version(self) -> None:
        def edit(lock: dict) -> None:  # type: ignore[type-arg]
            entry = lock["packages"]["node_modules/express"]
            entry["dependencies"]["version"] = "^9.9.9"

        assert parse_changed_packages(_npm_diff(edit), "npm") == [("express", "4.18.0")]


class TestRequirementsParsing:
    def _added(self, *lines: str) -> list[tuple[str, str]]:
        diff = "--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1 +1,9 @@\n"
        diff += "".join(f"+{line}\n" for line in lines)
        return parse_changed_packages(diff, "pip")

    def test_exact_pin(self) -> None:
        assert self._added("requests==2.32.0") == [("requests", "2.32.0")]

    def test_pin_with_hashes_markers_and_comments(self) -> None:
        assert self._added(
            "requests==2.32.0 \\",
            "    --hash=sha256:aaaa",
            'idna==3.7 ; python_version >= "3.8"',
            "Certifi==2024.2.2  # ca bundle",
            "urllib3[socks]==2.2.1",
        ) == [
            ("requests", "2.32.0"),
            ("idna", "3.7"),
            ("certifi", "2024.2.2"),
            ("urllib3", "2.2.1"),
        ]

    def test_range_has_no_version_to_verify(self) -> None:
        assert self._added("django>=4.2", "flask~=3.0") == [("django", ""), ("flask", "")]

    def test_options_and_comments_are_not_packages(self) -> None:
        assert self._added("# pinned==1.0", "-r base.txt", "--index-url https://x/simple") == []


_PNPM_V9 = """\
lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      lodash:
        specifier: ^4.17.20
        version: 4.17.20

packages:

  '@scope/pkg@1.0.0':
    resolution: {integrity: sha512-SSSS}

  lodash@4.17.20:
    resolution: {integrity: sha512-AAAA}

snapshots:

  '@scope/pkg@1.0.0(react@18.2.0)':
    dependencies:
      react: 18.2.0

  lodash@4.17.20: {}
"""

_PNPM_V6 = """\
lockfileVersion: '6.0'

dependencies:
  lodash:
    specifier: ^4.17.20
    version: 4.17.20

packages:

  /@scope/pkg@1.0.0(react@18.2.0):
    resolution: {integrity: sha512-SSSS}
    dev: false

  /lodash@4.17.20:
    resolution: {integrity: sha512-AAAA}
    dev: false
"""

_PNPM_V5 = """\
lockfileVersion: 5.4

specifiers:
  lodash: ^4.17.20

packages:

  /@scope/pkg/1.0.0_react@18.2.0:
    resolution: {integrity: sha512-SSSS}
    dev: false

  /lodash/4.17.20:
    resolution: {integrity: sha512-AAAA}
    dev: false
"""


class TestPnpmFormats:
    @pytest.mark.parametrize("lock", [_PNPM_V9, _PNPM_V6, _PNPM_V5], ids=["v9", "v6", "v5"])
    def test_bump(self, lock: str) -> None:
        new = lock.replace("4.17.20", "4.17.21").replace("AAAA", "BBBB")
        assert parse_changed_packages(_full_diff(lock, new), "pnpm") == [("lodash", "4.17.21")]

    @pytest.mark.parametrize("lock", [_PNPM_V9, _PNPM_V6, _PNPM_V5], ids=["v9", "v6", "v5"])
    def test_scoped_package_with_peer_suffix(self, lock: str) -> None:
        new = lock.replace("SSSS", "TTTT")
        assert parse_changed_packages(_full_diff(lock, new), "pnpm") == [("@scope/pkg", "1.0.0")]

    def test_importer_change_is_not_a_package(self) -> None:
        new = _PNPM_V9.replace("specifier: ^4.17.20", "specifier: ^4.17.21")
        assert parse_changed_packages(_full_diff(_PNPM_V9, new), "pnpm") == []

    def test_git_reference_has_no_version_to_verify(self) -> None:
        new = _PNPM_V9.replace(
            "snapshots:",
            "  tool@https://codeload.github.com/o/tool/tar.gz/abc123:\n"
            "    resolution: {tarball: https://codeload.github.com/o/tool/tar.gz/abc123}\n"
            "\nsnapshots:",
        )
        assert parse_changed_packages(_full_diff(_PNPM_V9, new), "pnpm") == [("tool", "")]


_PIPFILE_LOCK: dict[str, object] = {
    "_meta": {"hash": {"sha256": "mmmm"}, "pipfile-spec": 6},
    "default": {
        "certifi": {"hashes": ["sha256:aaaa"], "version": "==2024.2.2"},
        "Requests": {"hashes": ["sha256:bbbb"], "index": "pypi", "version": "==2.31.0"},
    },
    "develop": {
        "pytest": {"hashes": ["sha256:cccc"], "version": "==8.0.0"},
    },
}


def _pipfile_diff(mutate: object) -> str:
    new = copy.deepcopy(_PIPFILE_LOCK)
    mutate(new)  # type: ignore[operator]
    return _full_diff(json.dumps(_PIPFILE_LOCK, indent=4), json.dumps(new, indent=4))


class TestPipfileLock:
    def test_ecosystem(self) -> None:
        assert detect_ecosystem("Pipfile.lock") == "pipenv"

    def test_bump(self) -> None:
        def bump(lock: dict) -> None:  # type: ignore[type-arg]
            lock["default"]["Requests"] = {"hashes": ["sha256:dddd"], "version": "==2.32.0"}

        assert parse_changed_packages(_pipfile_diff(bump), "pipenv") == [("requests", "2.32.0")]

    def test_develop_section(self) -> None:
        def bump(lock: dict) -> None:  # type: ignore[type-arg]
            lock["develop"]["pytest"]["version"] = "==8.1.0"

        assert parse_changed_packages(_pipfile_diff(bump), "pipenv") == [("pytest", "8.1.0")]

    def test_new_package(self) -> None:
        def add(lock: dict) -> None:  # type: ignore[type-arg]
            lock["default"]["idna"] = {"hashes": ["sha256:eeee"], "version": "==3.7"}

        assert parse_changed_packages(_pipfile_diff(add), "pipenv") == [("idna", "3.7")]

    def test_meta_change_is_not_a_package(self) -> None:
        def edit(lock: dict) -> None:  # type: ignore[type-arg]
            lock["_meta"]["hash"]["sha256"] = "nnnn"

        assert parse_changed_packages(_pipfile_diff(edit), "pipenv") == []


@pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
class TestVersionBumpIntegration:
    """A staged bump of an installed package is scanned, in a throwaway repo."""

    def test_staged_bump_is_scanned(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def git(*args: str) -> None:
            result = _git(
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgsign=false",
                *args,
                cwd=tmp_path,
            )
            assert result.returncode == 0, result.stderr

        lock = {
            "name": "demo",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo"},
                "node_modules/accepts": {"version": "1.3.8"},
                "node_modules/express": {
                    "version": "4.18.0",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.0.tgz",
                    "license": "MIT",
                    "engines": {"node": ">= 0.10.0"},
                    "integrity": "sha512-EEEE",
                },
            },
        }
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
        git("init", "-q")
        git("add", "package-lock.json")
        git("commit", "-q", "-m", "base")

        for name in ("accepts", "express"):
            pkg = tmp_path / "node_modules" / name
            pkg.mkdir(parents=True)
            (pkg / "index.js").write_text(
                "const payload = `\ufe00\ufe01\ufe02`;\n",
                encoding="utf-8",
            )

        # Only a line well below the package name changes, so the name is
        # outside git's default three lines of context.
        lock["packages"]["node_modules/express"]["integrity"] = "sha512-FFFF"  # type: ignore[index]
        lockfile.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
        git("add", "package-lock.json")

        monkeypatch.chdir(tmp_path)
        findings = scan_changed_deps(["package-lock.json"], Scanner(scan_deps=True))

        assert len(findings) == 3
        assert {f.package for f in findings} == {"express"}
