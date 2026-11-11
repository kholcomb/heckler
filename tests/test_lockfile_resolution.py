"""Locating the installed copy of a changed package, and failing when there is none.

Every fixture here is synthetic: hand-built stand-ins for a virtualenv, a
node_modules tree and a pnpm store, holding inert text files. Nothing is
installed or downloaded.
"""

from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from heckler import lockfile
from heckler.cli import main
from heckler.lockfile import (
    _path_site_packages,
    _same_python_version,
    get_lockfile_diff,
    parse_changed_packages,
    resolve_package,
    scan_changed_deps,
)
from heckler.scanner import Scanner

# Three variation selectors in a string literal: enough for the scanner to
# report, and nothing more than that.
PLANTED = "payload = `" + "".join(chr(cp) for cp in (0xFE01, 0xFE02, 0xFE03)) + "`\n"
CLEAN = "value = 1\n"

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not available")


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep the machine's own interpreters and any outer pre-commit run out of it."""
    monkeypatch.setattr(lockfile, "_path_site_packages", lambda: ())
    monkeypatch.delenv("PRE_COMMIT_FROM_REF", raising=False)
    monkeypatch.delenv("PRE_COMMIT_TO_REF", raising=False)
    yield
    _path_site_packages.cache_clear()


def make_venv(root: Path, name: str = ".venv") -> Path:
    """A stand-in for a virtualenv: ``pyvenv.cfg`` and an empty site-packages."""
    venv = root / name
    site_packages = venv / "lib" / "python3.12" / "site-packages"
    site_packages.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    return site_packages


def install(
    site_packages: Path,
    dist: str,
    version: str,
    files: dict[str, str],
    *,
    record: bool = True,
    top_level: str | None = None,
) -> None:
    """Lay files out the way an installer would, with ``.dist-info`` metadata."""
    info = site_packages / f"{dist}-{version}.dist-info"
    info.mkdir()
    for relative, content in files.items():
        path = site_packages / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    (info / "METADATA").write_text(f"Name: {dist}\nVersion: {version}\n", encoding="utf-8")
    if record:
        rows = [f"{relative},sha256=x,1" for relative in files]
        rows += [f"{info.name}/METADATA,,", f"{info.name}/RECORD,,", "../../bin/tool,sha256=x,1"]
        (info / "RECORD").write_text("\n".join(rows) + "\n", encoding="utf-8")
    if top_level is not None:
        (info / "top_level.txt").write_text(top_level, encoding="utf-8")


def extra_entry(site_packages: Path, name: str, files: dict[str, str]) -> Path:
    """A metadata directory of its own, as a package can ship one among its files."""
    info = site_packages / name
    info.mkdir()
    for filename, content in files.items():
        (info / filename).write_text(content, encoding="utf-8")
    return info


def harmless_module(site_packages: Path) -> Path:
    module = site_packages / "harmless"
    module.mkdir()
    (module / "__init__.py").write_text(CLEAN, encoding="utf-8")
    return module


def node_package(root: Path, relative: str, version: str | None, content: str = CLEAN) -> Path:
    pkg = root / relative
    pkg.mkdir(parents=True)
    (pkg / "index.js").write_text(content, encoding="utf-8")
    if version is not None:
        (pkg / "package.json").write_text(json.dumps({"version": version}), encoding="utf-8")
    return pkg


class TestResolvePython:
    def test_import_name_differs_from_distribution_name(self, tmp_path: Path) -> None:
        sp = make_venv(tmp_path)
        install(
            sp,
            "PyYAML",
            "6.0.1",
            {
                "yaml/__init__.py": PLANTED,
                "yaml/_speedups.so": "not text",
                "_yaml/__init__.py": CLEAN,
            },
        )
        targets, problem = resolve_package(
            "pyyaml", "6.0.1", "pip", str(tmp_path / "requirements.txt")
        )
        assert problem == ""
        assert set(targets) == {sp / "yaml" / "__init__.py", sp / "_yaml" / "__init__.py"}

    def test_hyphens_underscores_and_case_are_equivalent(self, tmp_path: Path) -> None:
        sp = make_venv(tmp_path)
        install(sp, "python_dateutil", "2.9.0", {"dateutil/__init__.py": CLEAN})
        targets, problem = resolve_package(
            "Python-DateUtil", "2.9.0", "poetry", str(tmp_path / "poetry.lock")
        )
        assert problem == ""
        assert targets == [sp / "dateutil" / "__init__.py"]

    def test_other_version_installed(self, tmp_path: Path) -> None:
        sp = make_venv(tmp_path)
        install(sp, "PyYAML", "6.0.1", {"yaml/__init__.py": PLANTED})
        targets, problem = resolve_package(
            "pyyaml", "6.0.2", "pip", str(tmp_path / "requirements.txt")
        )
        assert targets == []
        assert problem == "the installed version is 6.0.1"

    def test_not_installed(self, tmp_path: Path) -> None:
        make_venv(tmp_path)
        targets, problem = resolve_package(
            "heckler-no-such-package", "1.0", "pip", str(tmp_path / "requirements.txt")
        )
        assert (targets, problem) == ([], "it is not installed")

    def test_range_pin_accepts_whatever_is_installed(self, tmp_path: Path) -> None:
        sp = make_venv(tmp_path)
        install(sp, "heckler_sample", "3.1.4", {"heckler_sample.py": CLEAN})
        targets, problem = resolve_package(
            "heckler-sample", "", "pip", str(tmp_path / "requirements.txt")
        )
        assert (targets, problem) == ([sp / "heckler_sample.py"], "")

    def test_shared_namespace_is_narrowed_to_the_distribution(self, tmp_path: Path) -> None:
        sp = make_venv(tmp_path)
        install(sp, "ns_one", "1.0", {"ns/one/__init__.py": CLEAN})
        install(sp, "ns_two", "1.0", {"ns/two/__init__.py": PLANTED})
        targets, _ = resolve_package("ns-one", "1.0", "pip", str(tmp_path / "requirements.txt"))
        assert targets == [sp / "ns" / "one" / "__init__.py"]

    def test_top_level_txt_when_there_is_no_record(self, tmp_path: Path) -> None:
        sp = make_venv(tmp_path)
        install(
            sp,
            "heckler_legacy",
            "1.0",
            {"legacy_mod.py": CLEAN, "legacy_pkg/__init__.py": CLEAN},
            record=False,
            top_level="legacy_mod\nlegacy_pkg\n",
        )
        targets, problem = resolve_package(
            "heckler-legacy", "1.0", "pip", str(tmp_path / "requirements.txt")
        )
        assert problem == ""
        assert set(targets) == {sp / "legacy_mod.py", sp / "legacy_pkg"}

    def test_pipfile_lock_uses_the_python_environment(self, tmp_path: Path) -> None:
        sp = make_venv(tmp_path, "venv")
        install(sp, "heckler_sample", "1.0", {"heckler_sample.py": CLEAN})
        targets, problem = resolve_package(
            "heckler-sample", "1.0", "pipenv", str(tmp_path / "Pipfile.lock")
        )
        assert (targets, problem) == ([sp / "heckler_sample.py"], "")

    @pytest.mark.parametrize(
        ("left", "right", "same"),
        [
            ("1.0", "1.0.0", True),
            ("2.32.0", "2.32.0", True),
            ("1.0.0rc1", "1.0.0-rc.1", True),
            ("1.0.0+local", "1.0.0", True),
            ("2.31.0", "2.32.0", False),
            ("1.0", "1.0.1", False),
            ("1.0.0", "1.0.0rc1", False),
        ],
    )
    def test_version_comparison(self, left: str, right: str, same: bool) -> None:
        assert _same_python_version(left, right) is same


@pytest.mark.skipif(os.name == "nt", reason="uses a shell script as a stand-in interpreter")
class TestInterpretersOnPath:
    """Under pre-commit the project's environment is only reachable through PATH."""

    def _fake_python(self, bin_dir: Path, site_packages: Path) -> None:
        bin_dir.mkdir(parents=True, exist_ok=True)
        script = bin_dir / "python3"
        script.write_text(f'#!/bin/sh\necho "{site_packages}"\n', encoding="utf-8")
        script.chmod(0o755)

    def test_environment_found_through_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        site_packages = tmp_path / "elsewhere" / "site-packages"
        site_packages.mkdir(parents=True)
        install(site_packages, "heckler_sample", "1.0", {"heckler_sample.py": PLANTED})
        self._fake_python(tmp_path / "bin", site_packages)

        monkeypatch.undo()  # drop the autouse stub; this test is about the real lookup
        monkeypatch.setenv("PATH", str(tmp_path / "bin"))
        _path_site_packages.cache_clear()

        project = tmp_path / "project"
        project.mkdir()
        targets, problem = resolve_package(
            "heckler-sample", "1.0", "pip", str(project / "requirements.txt")
        )
        assert (targets, problem) == ([site_packages / "heckler_sample.py"], "")

    def test_own_environment_is_not_asked_twice(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._fake_python(tmp_path / "bin", tmp_path / "unused")
        monkeypatch.undo()
        monkeypatch.setenv("PATH", str(tmp_path / "bin"))
        monkeypatch.setattr(sys, "executable", str(tmp_path / "bin" / "python3"))
        _path_site_packages.cache_clear()
        assert _path_site_packages() == ()


class TestInterpreterQuery:
    """Another interpreter is asked for its packages from inside the tree being checked."""

    def test_names_in_the_working_directory_are_not_imported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        expected = lockfile._query_interpreter(sys.executable)
        assert expected
        # Plain text under the names the query imports. Read as a module it
        # would not compile, and the query would come back empty.
        for name in ("site.py", "sysconfig.py", "threading.py"):
            (tmp_path / name).write_text("This is not Python.\n", encoding="utf-8")
        assert lockfile._query_interpreter(sys.executable) == expected

    def test_working_directory_leaves_the_path_before_any_other_import(self) -> None:
        statements = ast.parse(lockfile._SITE_PACKAGES_QUERY).body
        cleared = next(
            index
            for index, statement in enumerate(statements)
            if isinstance(statement, ast.Assign)
            and ast.unparse(statement.targets[0]) == "sys.path[:]"
        )
        # sys is built in, so importing it reads nothing from the path.
        assert [ast.unparse(statement) for statement in statements[:cleared]] == ["import sys"]


class TestResolveNode:
    def test_matching_version(self, tmp_path: Path) -> None:
        pkg = node_package(tmp_path, "node_modules/express", "4.18.2")
        lock = str(tmp_path / "package-lock.json")
        assert resolve_package("express", "4.18.2", "npm", lock) == ([pkg], "")

    def test_stale_install_is_not_scanned_in_its_place(self, tmp_path: Path) -> None:
        node_package(tmp_path, "node_modules/express", "4.18.0")
        lock = str(tmp_path / "package-lock.json")
        assert resolve_package("express", "4.18.2", "npm", lock) == (
            [],
            "the installed version is 4.18.0",
        )

    def test_not_installed(self, tmp_path: Path) -> None:
        lock = str(tmp_path / "package-lock.json")
        assert resolve_package("express", "4.18.2", "npm", lock) == ([], "it is not installed")

    def test_missing_package_json_cannot_be_checked_and_is_scanned(self, tmp_path: Path) -> None:
        pkg = node_package(tmp_path, "node_modules/express", None)
        lock = str(tmp_path / "package-lock.json")
        assert resolve_package("express", "4.18.2", "npm", lock) == ([pkg], "")

    def test_pnpm_virtual_store(self, tmp_path: Path) -> None:
        store = "node_modules/.pnpm"
        node_package(tmp_path, f"{store}/lodash@4.17.210/node_modules/lodash", "4.17.210")
        wanted = node_package(tmp_path, f"{store}/lodash@4.17.21/node_modules/lodash", "4.17.21")
        scoped = node_package(
            tmp_path, f"{store}/@scope+pkg@1.0.0_react@18.2.0/node_modules/@scope/pkg", "1.0.0"
        )
        lock = str(tmp_path / "pnpm-lock.yaml")
        assert resolve_package("lodash", "4.17.21", "pnpm", lock) == ([wanted], "")
        assert resolve_package("@scope/pkg", "1.0.0", "pnpm", lock) == ([scoped], "")

    def test_yarn_nested_second_version(self, tmp_path: Path) -> None:
        node_package(tmp_path, "node_modules/lodash", "4.17.21")
        nested = node_package(tmp_path, "node_modules/old-dep/node_modules/lodash", "3.10.1")
        lock = str(tmp_path / "yarn.lock")
        assert resolve_package("lodash", "3.10.1", "yarn", lock) == ([nested], "")


def _git(repo: Path, *args: str) -> None:
    result = subprocess.run(
        [
            "git",
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=10,
        cwd=repo,
    )
    assert result.returncode == 0, result.stderr


def _npm_lock(version: str) -> str:
    lock = {
        "name": "demo",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo"},
            "node_modules/express": {"version": version, "integrity": f"sha512-{version}"},
        },
    }
    return json.dumps(lock, indent=2) + "\n"


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A throwaway git repository with one committed lockfile, as the working directory."""
    (tmp_path / "package-lock.json").write_text(_npm_lock("4.18.0"), encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("heckler-sample==1.0\n", encoding="utf-8")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "package-lock.json", "requirements.txt")
    _git(tmp_path, "commit", "-q", "-m", "base")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _stage_npm_bump(repo: Path) -> None:
    (repo / "package-lock.json").write_text(_npm_lock("4.18.2"), encoding="utf-8")
    _git(repo, "add", "package-lock.json")


@needs_git
class TestScanChangedDeps:
    def test_python_bump_is_scanned_in_the_project_virtualenv(self, repo: Path) -> None:
        sp = make_venv(repo)
        install(sp, "heckler_sample", "1.1", {"sample_impl/__init__.py": PLANTED})
        (repo / "requirements.txt").write_text("heckler-sample==1.1\n", encoding="utf-8")
        _git(repo, "add", "requirements.txt")

        unscanned: list[str] = []
        findings = scan_changed_deps(["requirements.txt"], Scanner(scan_deps=True), unscanned)

        assert unscanned == []
        assert len(findings) == 3
        assert {f.package for f in findings} == {"heckler-sample"}
        assert all(f.source == "dependency" for f in findings)

    def test_stale_node_install_is_reported_not_scanned(self, repo: Path) -> None:
        node_package(repo, "node_modules/express", "4.18.0", PLANTED)
        _stage_npm_bump(repo)

        unscanned: list[str] = []
        findings = scan_changed_deps(["package-lock.json"], Scanner(scan_deps=True), unscanned)

        assert findings == []
        assert unscanned == [
            "express 4.18.2 changed in package-lock.json but was not scanned: "
            "the installed version is 4.18.0"
        ]

    def test_commit_range_from_pre_commit(
        self, repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stage_npm_bump(repo)
        _git(repo, "commit", "-q", "-m", "bump")
        assert get_lockfile_diff("package-lock.json") == ""

        monkeypatch.setenv("PRE_COMMIT_FROM_REF", "HEAD~1")
        monkeypatch.setenv("PRE_COMMIT_TO_REF", "HEAD")
        diff = get_lockfile_diff("package-lock.json")
        assert parse_changed_packages(diff, "npm") == [("express", "4.18.2")]


@needs_git
class TestDiffOnlyExitCodes:
    ARGS = ["--scan-deps", "--diff-only", "package-lock.json"]

    def test_unscanned_package_fails_ci(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _stage_npm_bump(repo)
        assert main(["--ci", *self.ARGS]) == 2
        captured = capsys.readouterr()
        assert "express 4.18.2 changed in package-lock.json" in captured.err
        assert "--allow-unscanned" in captured.err
        assert "No dangerous" not in captured.out

    def test_allow_unscanned_passes(self, repo: Path) -> None:
        _stage_npm_bump(repo)
        assert main(["--ci", "--allow-unscanned", *self.ARGS]) == 0

    def test_without_ci_only_warns(self, repo: Path) -> None:
        _stage_npm_bump(repo)
        assert main(self.ARGS) == 0

    def test_findings_still_exit_1(self, repo: Path) -> None:
        node_package(repo, "node_modules/express", "4.18.2", PLANTED)
        _stage_npm_bump(repo)
        assert main(["--ci", *self.ARGS]) == 1

    def test_clean_scanned_package_passes(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        node_package(repo, "node_modules/express", "4.18.2")
        _stage_npm_bump(repo)
        assert main(["--ci", *self.ARGS]) == 0
        assert "No dangerous" in capsys.readouterr().out

    def test_json_output_is_still_emitted_when_nothing_was_scanned(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _stage_npm_bump(repo)
        assert main(["--ci", "--format", "json", *self.ARGS]) == 2
        assert json.loads(capsys.readouterr().out) == []

    def test_unchanged_lockfile_passes(self, repo: Path) -> None:
        assert main(["--ci", *self.ARGS]) == 0


class TestAllText:
    """--all-text reaches the files of a changed Python package that have no source extension."""

    FILES = {
        "sample_impl/__init__.py": CLEAN,
        "sample_impl/templates/page.tmpl": PLANTED,
        "sample_impl/LICENSE": CLEAN,
        "sample_impl/_native.so": "ELF" + chr(0) * 8 + PLANTED,
    }

    def test_only_source_extensions_by_default(self, tmp_path: Path) -> None:
        sp = make_venv(tmp_path)
        install(sp, "heckler_sample", "1.0", self.FILES)
        lock = str(tmp_path / "requirements.txt")
        targets, problem = resolve_package("heckler-sample", "1.0", "pip", lock)
        assert (targets, problem) == ([sp / "sample_impl" / "__init__.py"], "")

    def test_every_text_file_with_all_text(self, tmp_path: Path) -> None:
        sp = make_venv(tmp_path)
        install(sp, "heckler_sample", "1.0", self.FILES)
        lock = str(tmp_path / "requirements.txt")
        targets, problem = resolve_package("heckler-sample", "1.0", "pip", lock, all_text=True)
        assert problem == ""
        names = sorted(target.relative_to(sp).as_posix() for target in targets)
        assert names == [
            "heckler_sample-1.0.dist-info/METADATA",
            "heckler_sample-1.0.dist-info/RECORD",
            "sample_impl/LICENSE",
            "sample_impl/__init__.py",
            "sample_impl/templates/page.tmpl",
        ]

    def test_pth_file_is_scanned_by_default(self, tmp_path: Path) -> None:
        sp = make_venv(tmp_path)
        install(sp, "heckler_sample", "1.0", {"heckler_sample_init.pth": PLANTED})
        lock = str(tmp_path / "requirements.txt")
        targets, _ = resolve_package("heckler-sample", "1.0", "pip", lock)
        assert targets == [sp / "heckler_sample_init.pth"]

    @needs_git
    def test_diff_only_all_text_from_the_command_line(self, repo: Path) -> None:
        sp = make_venv(repo)
        install(sp, "heckler_sample", "1.1", self.FILES)
        (repo / "requirements.txt").write_text("heckler-sample==1.1\n", encoding="utf-8")
        _git(repo, "add", "requirements.txt")
        args = ["--ci", "--scan-deps", "--diff-only", "requirements.txt"]

        assert main(args) == 0
        assert main(["--all-text", *args]) == 1

    @needs_git
    def test_bare_requirement_is_scanned_at_whatever_version_is_installed(self, repo: Path) -> None:
        """A line without a pin used to be passed over, and its package with it."""
        sp = make_venv(repo)
        install(sp, "heckler_sample", "7.0", {"sample_impl/__init__.py": PLANTED})
        (repo / "requirements.txt").write_text("heckler-sample\n", encoding="utf-8")
        _git(repo, "add", "requirements.txt")

        unscanned: list[str] = []
        findings = scan_changed_deps(["requirements.txt"], Scanner(scan_deps=True), unscanned)
        assert unscanned == []
        assert len(findings) == 3


# The name of an entry that sorts ahead of "heckler_sample-1.0.dist-info",
# since "-" comes before ".". A package can ship one among its own files.
EARLIER_ENTRY = "heckler_sample-1.0-py3.12.egg-info"
IDENTITY = "Name: heckler-sample\nVersion: 1.0\n"


class TestMoreThanOneEntryForAName:
    """No entry that goes by a package's name keeps another from being scanned."""

    @staticmethod
    def resolve(root: Path) -> tuple[list[Path], str]:
        return resolve_package("heckler-sample", "1.0", "pip", str(root / "requirements.txt"))

    def test_entry_that_sorts_first_does_not_stand_in_for_the_distribution(
        self, tmp_path: Path
    ) -> None:
        assert EARLIER_ENTRY < "heckler_sample-1.0.dist-info"
        sp = make_venv(tmp_path)
        install(sp, "heckler_sample", "1.0", {"sample_impl/__init__.py": PLANTED})
        harmless = harmless_module(sp)
        extra_entry(sp, EARLIER_ENTRY, {"PKG-INFO": IDENTITY, "top_level.txt": "harmless\n"})

        targets, problem = self.resolve(tmp_path)
        assert problem == ""
        assert set(targets) == {harmless, sp / "sample_impl" / "__init__.py"}

    def test_file_with_a_metadata_name_is_not_metadata(self, tmp_path: Path) -> None:
        sp = make_venv(tmp_path)
        install(sp, "heckler_sample", "1.0", {"sample_impl/__init__.py": PLANTED})
        (sp / EARLIER_ENTRY).write_text(IDENTITY, encoding="utf-8")
        assert self.resolve(tmp_path) == ([sp / "sample_impl" / "__init__.py"], "")

    @pytest.mark.parametrize(
        ("directory_name", "directory_version"),
        [
            ("heckler_sample", "9.9"),  # another version than its metadata file gives
            ("heckler_sample_plus", "1.0"),  # a name that only starts with the project's
        ],
    )
    def test_distribution_is_known_by_its_metadata_file_too(
        self, tmp_path: Path, directory_name: str, directory_version: str
    ) -> None:
        """An installer checks the metadata file, and the directory name far less."""
        sp = make_venv(tmp_path)
        install(sp, directory_name, directory_version, {"sample_impl/__init__.py": PLANTED})
        info = sp / f"{directory_name}-{directory_version}.dist-info"
        (info / "METADATA").write_text(IDENTITY, encoding="utf-8")
        assert self.resolve(tmp_path) == ([sp / "sample_impl" / "__init__.py"], "")

        harmless = harmless_module(sp)
        extra_entry(sp, EARLIER_ENTRY, {"PKG-INFO": IDENTITY, "top_level.txt": "harmless\n"})
        targets, problem = self.resolve(tmp_path)
        assert problem == ""
        assert set(targets) == {harmless, sp / "sample_impl" / "__init__.py"}

    def test_entry_in_another_directory_of_the_environment(self, tmp_path: Path) -> None:
        """One environment has a directory for pure Python and one for compiled code."""
        first = make_venv(tmp_path)
        second = tmp_path / ".venv" / "lib64" / "python3.12" / "site-packages"
        second.mkdir(parents=True)
        harmless = harmless_module(first)
        extra_entry(first, EARLIER_ENTRY, {"PKG-INFO": IDENTITY, "top_level.txt": "harmless\n"})
        install(second, "heckler_sample", "1.0", {"sample_impl/__init__.py": PLANTED})

        targets, problem = self.resolve(tmp_path)
        assert problem == ""
        assert set(targets) == {harmless, second / "sample_impl" / "__init__.py"}

    @needs_git
    def test_findings_are_reported_once_and_fail_the_run(self, repo: Path) -> None:
        sp = make_venv(repo)
        install(sp, "heckler_sample", "1.1", {"sample_impl/__init__.py": PLANTED})
        # Names the directory that holds the file the other entry lists.
        extra_entry(sp, "heckler_sample-1.1-py3.12.egg-info", {"top_level.txt": "sample_impl\n"})
        (repo / "requirements.txt").write_text("heckler-sample==1.1\n", encoding="utf-8")
        _git(repo, "add", "requirements.txt")

        unscanned: list[str] = []
        findings = scan_changed_deps(["requirements.txt"], Scanner(scan_deps=True), unscanned)
        assert unscanned == []
        assert len(findings) == 3
        assert main(["--ci", "--scan-deps", "--diff-only", "requirements.txt"]) == 1

    def test_each_lookup_sees_what_is_installed_now(self, tmp_path: Path) -> None:
        sp = make_venv(tmp_path)
        assert self.resolve(tmp_path) == ([], "it is not installed")
        install(sp, "heckler_sample", "1.0", {"heckler_sample.py": CLEAN})
        assert self.resolve(tmp_path) == ([sp / "heckler_sample.py"], "")

    def test_headers_are_read_at_least_as_far_as_an_installer_reads_them(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "METADATA").write_text(
            "Metadata-Version: 2.1\n"
            " \n"  # not an empty line: the headers go on
            "NAME:\n heckler-sample\n"  # in capitals, and folded
            "Version: 1.0\n"
            "Name: Another.Name\n"
            "\n"
            "Name: in-the-description\n",
            encoding="utf-8",
        )
        assert lockfile._declared(tmp_path) == (["heckler-sample", "Another.Name"], ["1.0"])


class TestMetadataThatListsNothing:
    """Metadata that leads to no installed file is a package that was not scanned."""

    ENTRY = "heckler_sample-1.0.dist-info"
    PROBLEM = f"{ENTRY} does not say which files it installed"

    @staticmethod
    def resolve(root: Path) -> tuple[list[Path], str]:
        return resolve_package("heckler-sample", "1.0", "pip", str(root / "requirements.txt"))

    @pytest.mark.parametrize(
        "lists",
        [
            {},
            {"RECORD": "gone/__init__.py,sha256=x,1\n"},
            {"top_level.txt": "gone\n"},
        ],
        ids=["no list", "nothing in RECORD exists", "nothing in top_level.txt exists"],
    )
    def test_is_not_a_clean_result(self, tmp_path: Path, lists: dict[str, str]) -> None:
        sp = make_venv(tmp_path)
        extra_entry(sp, self.ENTRY, {"METADATA": IDENTITY, **lists})
        assert self.resolve(tmp_path) == ([], self.PROBLEM)

    def test_module_list_does_not_lead_out_of_site_packages(self, tmp_path: Path) -> None:
        sp = make_venv(tmp_path)
        outside = tmp_path / "outside"
        outside.mkdir()
        names = f"..\n../../../../outside\n{outside}\n"
        extra_entry(sp, self.ENTRY, {"METADATA": IDENTITY, "top_level.txt": names})
        assert self.resolve(tmp_path) == ([], self.PROBLEM)

    def test_installed_files_that_are_not_code_are_not_a_failure(self, tmp_path: Path) -> None:
        sp = make_venv(tmp_path)
        install(sp, "heckler_sample", "1.0", {"sample_impl/_native.so": "not text"})
        assert self.resolve(tmp_path) == ([], "")

    def test_metadata_in_a_single_file_leaves_the_directory_named_after_the_package(
        self, tmp_path: Path
    ) -> None:
        sp = make_venv(tmp_path)
        (sp / "heckler_sample-1.0.egg-info").write_text(IDENTITY, encoding="utf-8")
        package = sp / "heckler_sample"
        package.mkdir()
        (package / "__init__.py").write_text(CLEAN, encoding="utf-8")
        assert self.resolve(tmp_path) == ([package], "")

    @needs_git
    def test_fails_the_run(self, repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
        sp = make_venv(repo)
        extra_entry(
            sp,
            "heckler_sample-1.1.dist-info",
            {"METADATA": "Name: heckler-sample\nVersion: 1.1\n"},
        )
        (repo / "requirements.txt").write_text("heckler-sample==1.1\n", encoding="utf-8")
        _git(repo, "add", "requirements.txt")

        assert main(["--ci", "--scan-deps", "--diff-only", "requirements.txt"]) == 2
        captured = capsys.readouterr()
        assert (
            "heckler-sample 1.1 changed in requirements.txt but was not scanned:"
            " heckler_sample-1.1.dist-info does not say which files it installed"
        ) in captured.err
        assert "No dangerous" not in captured.out
