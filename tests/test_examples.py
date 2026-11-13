"""The example workflow names its lockfiles in three places and makes a few promises.

These tests read examples/dependency-scan.yml as text, since the project has
no YAML parser to depend on, and keep the lists equal and the promises kept.
The report script inside it is run on hand-written JSON. Nothing is
installed, downloaded or scanned here.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
WORKFLOW = (REPO_ROOT / "examples" / "dependency-scan.yml").read_text(encoding="utf-8")
CI = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")


def _trigger_paths(trigger: str) -> list[str]:
    """The entries of the ``paths:`` list under ``on.<trigger>``."""
    block = re.search(
        rf"^  {trigger}:\n(?:    (?!paths:).*\n)*    paths:\n((?:      - .*\n)+)",
        WORKFLOW,
        re.MULTILINE,
    )
    assert block, f"paths: list of {trigger} not found"
    return re.findall(r"- '([^']+)'", block.group(1))


def _run_script(step: str) -> str:
    """The ``run:`` script of the step called *step*, without its indentation."""
    block = re.search(
        rf"^      - name: {re.escape(step)}\n(?:        .*\n)*?        run: \|(?:  #.*)?\n"
        r"((?:(?:          .*)?\n)+)",
        WORKFLOW,
        re.MULTILINE,
    )
    assert block, f"run: script of the step {step!r} not found"
    return textwrap.dedent(block.group(1))


INSTALL = _run_script("Install dependencies without running their code")
SCAN = _run_script("Scan dependencies")


class TestLinted:
    """CI hands every workflow under examples/ to both linters."""

    def test_every_example_is_named_to_both_linters(self) -> None:
        examples = sorted(
            path.relative_to(REPO_ROOT).as_posix()
            for suffix in ("*.yml", "*.yaml")
            for path in (REPO_ROOT / "examples").rglob(suffix)
        )
        assert examples
        actionlint = " ".join(re.findall(r"^ +args: (-color.*)$", CI, re.MULTILINE)).split()
        zizmor = " ".join(re.findall(r"^ +run: (zizmor --offline.*)$", CI, re.MULTILINE)).split()
        for name in examples:
            assert name in actionlint, f"actionlint is not given {name}"
            assert name in zizmor, f"zizmor is not given {name}"


class TestLockfileLists:
    """What starts the workflow has to be what its install step can install from."""

    def test_both_triggers_name_the_same_lockfiles(self) -> None:
        assert _trigger_paths("pull_request")
        assert _trigger_paths("pull_request") == _trigger_paths("push")

    def test_install_step_handles_exactly_the_listed_lockfiles(self) -> None:
        handled = set(re.findall(r"\[ -f (\S+) \]", INSTALL))
        handled |= set(re.findall(r"compgen -G '([^']+)'", INSTALL))
        assert handled == set(_trigger_paths("pull_request"))


class TestPromises:
    """The header of the workflow says these; a later edit should not quietly undo them."""

    def test_node_installs_run_no_package_scripts(self) -> None:
        installs = re.findall(r"(?:npm ci|pnpm install|yarn install)[^;\n]*", INSTALL)
        assert len(installs) == 4, installs
        for command in installs:
            assert "--ignore-scripts" in command or "--mode=skip-build" in command, command

    @pytest.mark.parametrize(
        "setting",
        ["PIP_ONLY_BINARY: ':all:'", "POETRY_INSTALLER_ONLY_BINARY: ':all:'", "UV_NO_BUILD: '1'"],
    )
    def test_python_installs_take_wheels_only(self, setting: str) -> None:
        assert setting in WORKFLOW

    def test_token_is_read_only_and_not_left_in_the_checkout(self) -> None:
        assert "\npermissions:\n  contents: read\n" in WORKFLOW
        assert "persist-credentials: false" in WORKFLOW

    def test_results_are_not_cached(self) -> None:
        assert "actions/cache" not in WORKFLOW

    def test_only_what_was_installed_is_scanned(self) -> None:
        assert 'heckler --ci --scan-deps --format json "${dirs[@]}"' in SCAN

    def test_a_run_with_nothing_to_scan_fails(self) -> None:
        nothing_installed = INSTALL[INSTALL.index('if [ "${#dirs[@]}" -eq 0 ]') :]
        assert nothing_installed.count("exit 2") == 2


def _finding(**changes: object) -> dict[str, object]:
    finding: dict[str, object] = {
        "file": "node_modules/pkg/index.js",
        "line": 3,
        "column": 5,
        "codepoint": "U+200B",
        "name": "Zero Width Space",
        "category": "zero_width",
        "severity": "medium",
        "source": "dependency",
        "package": "pkg",
    }
    finding.update(changes)
    return finding


class TestReport:
    """The job summary is written by a Python script inside the scan step."""

    CLEAN = "No dangerous invisible Unicode characters found"

    @staticmethod
    def _script() -> str:
        program = re.search(r"<<'PY'\n(.*?\n)PY\n", SCAN, re.DOTALL)
        assert program, "report script not found in the scan step"
        return program.group(1)

    def _report(
        self, tmp_path: Path, content: str | None, status: int
    ) -> subprocess.CompletedProcess[str]:
        result = tmp_path / "result.json"
        if content is not None:
            result.write_text(content, encoding="utf-8")
        return subprocess.run(
            [sys.executable, "-", str(result), str(status)],
            input=self._script(),
            capture_output=True,
            text=True,
            check=False,
        )

    def test_clean(self, tmp_path: Path) -> None:
        report = self._report(tmp_path, "[]", 0)
        assert report.returncode == 0
        assert self.CLEAN in report.stdout

    def test_findings_are_listed(self, tmp_path: Path) -> None:
        report = self._report(tmp_path, json.dumps([_finding()]), 1)
        assert report.returncode == 0
        assert "**1 dangerous character(s) found in dependencies.**" in report.stdout
        row = "| pkg | node_modules/pkg/index.js | 3 | U+200B (Zero Width Space) | MEDIUM |"
        assert row in report.stdout
        assert self.CLEAN not in report.stdout

    def test_a_finding_outside_any_package(self, tmp_path: Path) -> None:
        report = self._report(tmp_path, json.dumps([_finding(package=None)]), 1)
        assert "| - | node_modules/pkg/index.js |" in report.stdout

    def test_a_name_cannot_break_out_of_its_cell(self, tmp_path: Path) -> None:
        finding = _finding(file="node_modules/pkg/a|b`c\nd.js")
        report = self._report(tmp_path, json.dumps([finding]), 1)
        assert "| node_modules/pkg/a\\|b'c d.js |" in report.stdout

    def test_a_long_list_is_cut_short_and_says_so(self, tmp_path: Path) -> None:
        findings = [_finding(line=number) for number in range(1, 61)]
        report = self._report(tmp_path, json.dumps(findings), 1)
        assert "**60 dangerous character(s) found in dependencies.**" in report.stdout
        assert report.stdout.count("| pkg |") == 50
        assert "Only the first 50 are listed." in report.stdout

    @pytest.mark.parametrize("content", [None, "", "[]"], ids=["no file", "empty", "empty list"])
    def test_a_scan_that_did_not_finish_is_not_clean(
        self, tmp_path: Path, content: str | None
    ) -> None:
        report = self._report(tmp_path, content, 2)
        assert report.returncode == 0  # the step then exits with heckler's own code
        assert "The scan did not finish: heckler exited with code 2." in report.stdout
        assert self.CLEAN not in report.stdout

    @pytest.mark.parametrize(
        ("content", "status"),
        [
            ("not json", 0),
            ("", 0),
            ("{}", 0),
            ("[]", 1),
            (json.dumps([_finding()]), 0),
            (None, 0),
        ],
        ids=[
            "not json",
            "empty",
            "not a list",
            "code 1, no findings",
            "code 0, findings",
            "no file",
        ],
    )
    def test_a_report_that_cannot_be_trusted_fails_the_step(
        self, tmp_path: Path, content: str | None, status: int
    ) -> None:
        report = self._report(tmp_path, content, status)
        assert report.returncode != 0
        assert "The scan result cannot be used" in report.stdout
        assert self.CLEAN not in report.stdout
