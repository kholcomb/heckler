"""The shipped pre-commit hooks put names chosen by a repository's author on the command line.

Each hook's entry ends with --, so every name pre-commit adds after it is a
path, and none is read as an option, whatever it starts with.
"""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

import pytest

from heckler import lockfile, scanner, vet
from heckler.cli import main

REPO_ROOT = Path(__file__).parent.parent
MANIFEST = (REPO_ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")
CRITICAL = "# " + chr(0x202E) + "\n"
HIGH = "# " + chr(0x200F) + "\n"


def _entries() -> dict[str, list[str]]:
    """Each hook's id and its entry, split as pre-commit splits it."""
    found: dict[str, list[str]] = {}
    for block in re.split(r"^- id: ", MANIFEST, flags=re.MULTILINE)[1:]:
        hook_id = block.split("\n", 1)[0].strip()
        entry = re.search(r"^  entry: (.+)$", block, re.MULTILINE)
        assert entry, f"no entry: in the {hook_id} hook"
        found[hook_id] = shlex.split(entry.group(1))
    return found


def _run(hook: str, names: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    """The hook's entry, then the names, as pre-commit builds the command."""
    command = _entries()[hook]
    assert command[0] == "heckler"
    try:
        code = main(command[1:] + names)
    except SystemExit as stop:  # argparse's --help and --version
        code = stop.code if isinstance(stop.code, int) else 2
    out, err = capsys.readouterr()
    return code, out, err


def _npm_diff(name: str, version: str) -> str:
    """An all-added lockfile v3 diff, the shape of tests/test_names_in_output.py::_diff."""
    lines = ["+{", '+  "lockfileVersion": 3,', '+  "packages": {']
    lines += [f'+    "node_modules/{name}": {{', f'+      "version": "{version}"', "+    }"]
    lines += ["+  }", "+}"]
    return "\n".join(lines) + "\n"


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A repository root: planted.py (CRITICAL), planted_high.py (HIGH), evil.yml, big.py."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setattr(scanner, "_MAX_SCAN_FILE_SIZE", 1000)
    (tmp_path / "planted.py").write_text(CRITICAL, encoding="utf-8")
    (tmp_path / "planted_high.py").write_text(HIGH, encoding="utf-8")
    (tmp_path / "evil.yml").write_text('allowlist: ["*.py"]\n', encoding="utf-8")
    (tmp_path / "big.py").write_text("x = 1\n" * 500, encoding="utf-8")  # 3,000 bytes
    return tmp_path


def _make(name: str) -> None:
    """The dash-led file, or for "-hf/notes.md" the directory and the file in it."""
    path = Path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("note\n", encoding="utf-8")


def test_each_entry_ends_with_end_of_options() -> None:
    entries = _entries()
    assert set(entries) == {"heckler", "heckler-lockfile"}
    for hook, command in entries.items():
        assert command[0] == "heckler", hook
        assert command[-1] == "--", hook
        assert command.count("--") == 1, hook


# (name, the file beside it, exit code with --)
SOURCE_CASES = [
    ("--version", "planted.py", 1),
    ("--help", "planted.py", 1),
    ("-hq", "planted.py", 1),
    ("-hf/notes.md", "planted.py", 1),
    ("--severity=critical", "planted_high.py", 1),
    ("--config=evil.yml", "planted.py", 1),
    ("--allow-unscanned", "big.py", 2),
    ("--", "planted.py", 1),  # (RF 2)
    ("-", "planted.py", 1),  # (RF 3)
]


class TestSourceHook:
    @pytest.mark.parametrize("first", [True, False], ids=["name first", "name last"])
    @pytest.mark.parametrize(("name", "beside", "expected"), SOURCE_CASES)
    def test_a_name_like_an_option_is_a_path(
        self,
        repo: Path,
        capsys: pytest.CaptureFixture[str],
        name: str,
        beside: str,
        expected: int,
        first: bool,
    ) -> None:
        _make(name)
        code, out, err = _run("heckler", [name, beside] if first else [beside, name], capsys)
        assert code == expected
        assert "usage: heckler" not in out
        assert not out.startswith("heckler ")
        assert beside in out + err

    def test_a_name_like_vet_downloads_nothing(  # (RF 4)
        self, repo: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def no_download(*args: object, **kwargs: object) -> list[Path]:
            pytest.fail("a file name started a download")

        monkeypatch.setattr(vet, "download_package", no_download)
        Path("--vet=pkg==1.0").write_text(CRITICAL, encoding="utf-8")
        code, out, _ = _run("heckler", ["--vet=pkg==1.0"], capsys)
        assert code == 1
        assert "--vet=pkg==1.0" in out


class TestLockfileHook:
    @pytest.mark.parametrize("first", [True, False], ids=["directory first", "directory last"])
    def test_a_lockfile_in_a_directory_like_an_option_is_read(
        self,
        repo: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
        first: bool,
    ) -> None:
        _make("-hf/package-lock.json")
        _make("package-lock.json")
        diff = _npm_diff("heckler-probe-missing", "9.9.9")
        monkeypatch.setattr(lockfile, "get_lockfile_diff", lambda path: diff)
        names = ["-hf/package-lock.json", "package-lock.json"]
        code, out, err = _run("heckler-lockfile", names if first else names[::-1], capsys)
        assert code == 2
        assert "changed in -hf/package-lock.json but was not scanned" in err
        assert "usage: heckler" not in out

    def test_a_finding_in_an_installed_package_is_reported(  # (RF 5)
        self, repo: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        package = repo / "node_modules" / "heckler-probe"
        package.mkdir(parents=True)
        (package / "package.json").write_text(
            json.dumps({"name": "heckler-probe", "version": "1.0.0"}), encoding="utf-8"
        )
        (package / "index.js").write_text("// " + chr(0x202E) + "\n", encoding="utf-8")
        _make("-hf/package-lock.json")
        _make("package-lock.json")
        diff = _npm_diff("heckler-probe", "1.0.0")
        monkeypatch.setattr(lockfile, "get_lockfile_diff", lambda path: diff)
        code, out, _ = _run(
            "heckler-lockfile", ["-hf/package-lock.json", "package-lock.json"], capsys
        )
        assert code == 1
        assert "pkg:heckler-probe" in out
