"""Tests for lockfile diff parsing."""

from __future__ import annotations

import json
import os
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
        diff = '''\
--- a/package-lock.json
+++ b/package-lock.json
@@ -1,5 +1,10 @@
+    "node_modules/lodash": {
+      "version": "4.17.21"
+    },
+    "node_modules/@scope/pkg": {
+      "version": "1.0.0"
     }
'''
        packages = parse_changed_packages(diff, "npm")
        names = [p[0] for p in packages]
        assert "lodash" in names
        assert "@scope/pkg" in names

    def test_pip_diff(self) -> None:
        diff = '''\
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,3 +1,5 @@
 flask==3.0.0
+requests==2.31.0
+django>=4.2
'''
        packages = parse_changed_packages(diff, "pip")
        names = [p[0] for p in packages]
        assert "requests" in names
        assert "django" in names

    def test_yarn_diff(self) -> None:
        diff = '''\
--- a/yarn.lock
+++ b/yarn.lock
@@ -1,5 +1,10 @@
+"lodash@^4.17.21":
+  version "4.17.21"
+"@babel/core@^7.24.0":
+  version "7.24.0"
'''
        packages = parse_changed_packages(diff, "yarn")
        names = [p[0] for p in packages]
        assert "lodash" in names
        assert "@babel/core" in names

    def test_pnpm_diff(self) -> None:
        diff = '''\
--- a/pnpm-lock.yaml
+++ b/pnpm-lock.yaml
@@ -1,5 +1,10 @@
+  /lodash@4.17.21:
+    resolution: {integrity: sha512-xxx}
+  /@scope/pkg@1.0.0:
+    resolution: {integrity: sha512-yyy}
'''
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
        ["git", *args], capture_output=True, text=True, timeout=10, cwd=cwd,
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
            lockfile_content = json.dumps({
                "name": "test",
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/heckler-test-pkg": {
                        "version": "1.0.0",
                    }
                }
            }, indent=2)
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
            lockfile_content = json.dumps({
                "name": "test",
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/lodash": {"version": "4.17.21"},
                    "node_modules/@scope/evil-pkg": {"version": "0.0.1"},
                }
            }, indent=2)
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
            renamed = False
            if not real_nm.exists():
                self.TEMP_NM.rename(real_nm)
                renamed = True
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
                result = resolve_package_dir("@scope/pkg", "npm", str(REPO_ROOT / "package-lock.json"))
                assert result is not None
                assert result.name == "pkg"
                real_nm.rename(self.TEMP_NM)
            else:
                pytest.skip("node_modules already exists in repo root")
        finally:
            self._cleanup()

    def test_returns_none_for_missing_package(self) -> None:
        result = resolve_package_dir("nonexistent-pkg-xyz", "npm", str(REPO_ROOT / "package-lock.json"))
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
                f'const payload = `\uFE00\uFE01\uFE0F`;\n',
                encoding="utf-8",
            )

            # 2. Create and stage a lockfile referencing it
            lockfile_content = json.dumps({
                "name": "test",
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/evil-pkg": {"version": "1.0.0"},
                }
            }, indent=2)
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
