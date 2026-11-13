"""A name is chosen by whoever made the file, the archive or the package.

Wherever heckler prints one for a person to read, its control and invisible
characters are spelled out as <U+XXXX>, so it cannot send an escape
sequence or a line break to the terminal.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

from heckler import lockfile, scanner, vet
from heckler._output import write_err, write_line
from heckler.characters import DANGEROUS_UNICODE_RE, Severity, ThreatCategory
from heckler.cli import build_parser, main
from heckler.formatters.text import _BOLD, _RESET, _SEVERITY_COLORS, format_text, spell_out
from heckler.scanner import Finding

ESC, CR, RLO = chr(0x1B), chr(0x0D), chr(0x202E)
NAME = f"e{ESC}[2K{CR}{RLO}"
SPELLED = "e<U+001B>[2K<U+000D><U+202E>"
# A lockfile diff is read by lines, so a name in one holds no line break.
LOCK_NAME = f"e{ESC}[2K{RLO}"
LOCK_SPELLED = "e<U+001B>[2K<U+202E>"
PLANTED = f"x = 1  # {RLO}\n"
Serve = Callable[[list[Path]], None]


def _tar_gz(path: Path, files: dict[str, bytes]) -> Path:
    with tarfile.open(path, "w:gz") as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return path


def _zip(path: Path, files: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return path


def _raw(text: str) -> list[str]:
    """The lines of *text* that hold a character a terminal acts on or does not draw."""
    return [
        line
        for line in text.split("\n")
        if any(not c.isprintable() or DANGEROUS_UNICODE_RE.match(c) for c in line)
    ]


def _named(directory: Path, name: str, content: str = PLANTED) -> Path:
    """Make the file *name*, or skip where the filesystem refuses such a name."""
    path = directory / name
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except OSError:
        pytest.skip("this filesystem does not take such a name")
    return path


@pytest.fixture
def serve(monkeypatch: pytest.MonkeyPatch) -> Serve:
    def install(archives: list[Path]) -> None:
        def fake(
            spec: str,
            registry: str,
            tmpdir: str,
            not_scanned: list[tuple[str, str]] | None = None,
        ) -> list[Path]:
            return archives

        monkeypatch.setattr(vet, "download_package", fake)

    return install


def _finding(**changes: object) -> Finding:
    fields: dict[str, object] = {
        "file": "test.js",
        "line": 1,
        "column": 5,
        "codepoint": 0xFE01,
        "codepoint_hex": "U+FE01",
        "char_name": "Variation Selector 2",
        "category": ThreatCategory.VARIATION_SELECTOR,
        "severity": Severity.CRITICAL,
        "line_content": 'const x = "";\n',
        "source": "project",
        "package": None,
    }
    fields.update(changes)
    return Finding(**fields)  # type: ignore[arg-type]


def _ours(text: str) -> str:
    """*text* without the colour codes heckler itself writes."""
    for code in (*_SEVERITY_COLORS.values(), _BOLD, _RESET):
        text = text.replace(code, "")
    return text


class TestTheWayOut:
    def test_write_err_spells_out_the_message(self, capsys: pytest.CaptureFixture[str]) -> None:
        write_err(f"Warning: {NAME}")
        assert capsys.readouterr().err == f"Warning: {SPELLED}\n"

    def test_write_line_spells_out_the_message(self, capsys: pytest.CaptureFixture[str]) -> None:
        write_line(f"  scanned: {NAME}")
        assert capsys.readouterr().out == f"  scanned: {SPELLED}\n"

    def test_a_name_spelled_out_twice_is_spelled_out_once(self) -> None:
        assert spell_out(spell_out(NAME)) == spell_out(NAME) == SPELLED


class TestPlainScan:
    def test_a_path_that_does_not_exist(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["--no-color", str(tmp_path / NAME)]) == 2
        err = capsys.readouterr().err
        assert SPELLED in err
        assert _raw(err) == []

    def test_a_config_file_that_does_not_exist(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["--config", str(tmp_path / f"{NAME}.yml"), str(tmp_path)]) == 2
        err = capsys.readouterr().err
        assert SPELLED in err
        assert _raw(err) == []

    def test_a_file_that_stops_the_scan_early(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _named(tmp_path, f"{NAME}.js", chr(0x200B) * 10_001 + "\n")
        main(["--no-color", "--quiet", str(tmp_path)])
        err = capsys.readouterr().err
        assert f"{SPELLED}.js: stopped after 10000 findings" in err
        assert _raw(err) == []

    def test_the_report_names_the_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = _named(tmp_path, f"{NAME}.py")
        for argv in (
            ["--no-color", str(tmp_path)],
            ["--no-color", "--ci", "--skip-binary", str(path)],
        ):
            main(argv)
            out = capsys.readouterr().out
            assert spell_out(str(path)) in out.splitlines()
            assert _raw(out) == []


class TestTextReport:
    def test_the_file_header(self) -> None:
        out = format_text([_finding(file=f"src/{NAME}.js")], color=False)
        assert f"src/{SPELLED}.js" in out.splitlines()
        assert _raw(out) == []

    def test_the_package(self) -> None:
        out = format_text([_finding(package=NAME, source="dependency")], color=False)
        assert f"pkg:{SPELLED}" in out
        assert _raw(out) == []

    def test_with_colour(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("FORCE_COLOR", "1")
        out = format_text([_finding(file=NAME, package=NAME)], color=True)
        assert f"{_BOLD}{SPELLED}{_RESET}" in out
        assert _raw(_ours(out)) == []

    def test_the_annotation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        out = format_text([_finding(file=f"src/{NAME}.js")], color=False)
        line = next(ln for ln in out.splitlines() if ln.startswith("::error "))
        assert line.startswith(f"::error file=src/{SPELLED}.js,line=1,col=5::")

    def test_a_name_that_is_not_utf8(self) -> None:
        """A lone surrogate, as a Linux file name can hold, reads as <U+DC80>."""
        out = format_text([_finding(file="x" + chr(0xDC80) + ".py")], color=False)
        assert "x<U+DC80>.py" in out.splitlines()

    def test_an_emoji_in_a_name(self) -> None:
        """The U+FE0F of an emoji is spelled out in a name, as it is in every note."""
        out = format_text([_finding(file=chr(0x2764) + chr(0xFE0F) + ".md")], color=False)
        assert chr(0x2764) + "<U+FE0F>.md" in out.splitlines()


class TestArgumentErrors:
    """argparse echoes back the argument it could not use."""

    @pytest.mark.parametrize(
        "argument, message",
        [
            pytest.param(f"-e{ESC}[2K{RLO}", "unrecognized arguments", id="unrecognized"),
            pytest.param(f"--s={NAME}", "ambiguous option", id="ambiguous"),
            pytest.param(f"--quiet=a{chr(0xFE01)}", "ignored explicit argument", id="explicit"),
        ],
    )
    def test_an_argument_that_cannot_be_used(
        self, argument: str, message: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with pytest.raises(SystemExit) as stop:
            main(["--no-color", argument])
        assert stop.value.code == 2
        captured = capsys.readouterr()
        assert message in captured.err
        assert "<U+" in captured.err
        assert _raw(captured.err) == []
        assert captured.out == ""

    def test_the_usage_is_not_coloured(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Python 3.14 colours the usage on a terminal; forced here as CI has none.

        Before 3.14 the parser never colours, so this passes there as it stands.
        """
        for name in ("NO_COLOR", "PYTHON_COLORS"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("FORCE_COLOR", "1")
        with pytest.raises(SystemExit) as stop:
            main(["--bogus"])
        assert stop.value.code == 2
        err = capsys.readouterr().err
        assert chr(0x1B) not in err
        assert "<U+001B>" not in err
        assert err.startswith("usage: heckler ")

    def test_an_invalid_choice(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as stop:
            main(["--format", f"a{chr(0xFE01)}"])
        assert stop.value.code == 2
        err = capsys.readouterr().err
        assert "invalid choice" in err
        assert _raw(err) == []

    def test_an_ordinary_bad_argument_reads_as_it_did(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with pytest.raises(SystemExit) as stop:
            main(["--bogus"])
        assert stop.value.code == 2
        assert (
            capsys.readouterr().err
            == build_parser().format_usage() + "heckler: error: unrecognized arguments: --bogus\n"
        )


def _vet(spec: str, capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    code = main(["--no-color", "--vet", spec])
    captured = capsys.readouterr()
    assert _raw(captured.out) == []
    assert _raw(captured.err) == []
    return code, captured.out, captured.err


def _refused_tar(tmp_path: Path) -> Path:
    return _tar_gz(tmp_path / "pkg-1.0.tgz", {f"package/{NAME}.js": b"/" * 1001})


def _refused_zip(tmp_path: Path) -> Path:
    return _zip(tmp_path / "pkg-1.0.zip", {f"{NAME}.py": b"/" * 1001})


def _escaping_zip(tmp_path: Path) -> Path:
    return _zip(tmp_path / "pkg-1.0.zip", {f"../{NAME}.py": b"x = 1\n"})


def _symlink_zip(tmp_path: Path) -> Path:
    path = tmp_path / "pkg-1.0.zip"
    with zipfile.ZipFile(path, "w") as zf:
        info = zipfile.ZipInfo(NAME)
        info.external_attr = 0o120777 << 16
        zf.writestr(info, b"target")
    return path


class TestVet:
    @pytest.mark.parametrize("build", [_refused_tar, _refused_zip, _escaping_zip, _symlink_zip])
    def test_an_archive_refused_for_a_member(
        self,
        build: Callable[[Path], Path],
        tmp_path: Path,
        serve: Serve,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # Only the first two archives are larger than this.
        monkeypatch.setattr(vet, "_MAX_EXTRACT_SIZE", 1000)
        serve([build(tmp_path)])
        code, _, err = _vet("pkg==1.0", capsys)
        assert code == 2
        assert SPELLED in err

    def test_a_member_left_out_as_binary(
        self, tmp_path: Path, serve: Serve, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _named(tmp_path / "probe", f"{NAME}.png")
        archive = _tar_gz(
            tmp_path / "pkg-1.0.tgz",
            {
                f"package/{NAME}.png": b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 4,
                "package/a.js": b"1;\n",
            },
        )
        serve([archive])
        code, out, _ = _vet("pkg==1.0", capsys)
        assert code == 0
        assert f"  binary, not scanned as text: pkg-1.0.tgz/package/{SPELLED}.png" in out

    def test_a_member_too_large_to_scan(
        self,
        tmp_path: Path,
        serve: Serve,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _named(tmp_path / "probe", f"{NAME}.js")
        monkeypatch.setattr(scanner, "_MAX_SCAN_FILE_SIZE", 1000)
        serve([_tar_gz(tmp_path / "pkg-1.0.tgz", {f"package/{NAME}.js": b"/" * 3000})])
        code, out, err = _vet("pkg==1.0", capsys)
        assert code == 2
        assert f"  not scanned: pkg-1.0.tgz/package/{SPELLED}.js" in out
        assert f"Warning: pkg-1.0.tgz/package/{SPELLED}.js was not scanned" in err

    def test_the_name_of_an_archive(
        self, tmp_path: Path, serve: Serve, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _named(tmp_path / "probe", f"{NAME}-1.0.tgz")
        serve([_tar_gz(tmp_path / f"{NAME}-1.0.tgz", {"package/a.js": b"1;\n"})])
        code, out, _ = _vet("pkg==1.0", capsys)
        assert code == 0
        assert f"  scanned: {SPELLED}-1.0.tgz" in out

    def test_the_spec_in_the_header(
        self, tmp_path: Path, serve: Serve, capsys: pytest.CaptureFixture[str]
    ) -> None:
        serve([_tar_gz(tmp_path / "pkg-1.0.tgz", {"package/a.js": b"1;\n"})])
        code, out, _ = _vet(f"pkg{NAME}==1.0", capsys)
        assert code == 0
        assert f"[VET] pkg{SPELLED}==1.0 (pypi)" in out

    def test_a_spec_with_no_registry(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, _, err = _vet(f"pkg{NAME}", capsys)
        assert code == 2
        assert f'"pkg{SPELLED}"' in err

    def test_a_checksum_mismatch(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        path = tmp_path / "data.bin"
        path.write_bytes(b"data")
        with pytest.raises(SystemExit):
            vet._verify_checksum(path, "sha256", "0" * 64, f"{NAME}.whl (pypi)")
        err = capsys.readouterr().err
        assert err.splitlines() == [
            f"Error: Checksum mismatch for {SPELLED}.whl (pypi)",
            "  Expected (sha256): " + "0" * 64,
            "  Got:                    " + hashlib.sha256(b"data").hexdigest(),
        ]

    def test_the_report_names_the_member(
        self, tmp_path: Path, serve: Serve, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _named(tmp_path / "probe", f"{NAME}.js")
        serve([_tar_gz(tmp_path / "pkg-1.0.tgz", {f"package/{NAME}.js": PLANTED.encode()})])
        code, out, _ = _vet("pkg==1.0", capsys)
        assert code == 1
        assert f"pkg-1.0.tgz/package/{SPELLED}.js" in out.splitlines()
        assert "pkg:pkg==1.0" in out
        assert _raw(out) == []


def _diff(*packages: tuple[str, str]) -> str:
    lines = ["+{", '+  "lockfileVersion": 3,', '+  "packages": {']
    for name, version in packages:
        lines += [f'+    "node_modules/{name}": {{', f'+      "version": "{version}"', "+    },"]
    lines += ["+  }", "+}"]
    return "\n".join(lines) + "\n"


class TestDiffOnly:
    @staticmethod
    def _run(
        lf: str, diff: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> str:
        monkeypatch.setattr(lockfile, "get_lockfile_diff", lambda path: diff)
        main(["--no-color", "--scan-deps", "--diff-only", lf])
        err = capsys.readouterr().err
        assert _raw(err) == []
        return err

    def test_a_lockfile_with_no_diff(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        lf = str(tmp_path / NAME / "package-lock.json")
        err = self._run(lf, "", monkeypatch, capsys)
        assert f"No diff available for {spell_out(lf)}. Skipping." in err

    def test_a_file_that_is_not_a_lockfile(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        err = self._run(f"weird{NAME}.lock", "", monkeypatch, capsys)
        assert f"weird{SPELLED}.lock was not scanned" in err

    def test_a_lockfile_heckler_cannot_parse(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        err = self._run(f"sub{NAME}/Cargo.lock", "", monkeypatch, capsys)
        assert (
            f"sub{SPELLED}/Cargo.lock was not scanned: cargo lockfiles are not supported yet" in err
        )

    def test_a_package_that_is_not_installed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        diff = _diff((f"missing{LOCK_NAME}", "1.0.0"))
        err = self._run(str(tmp_path / "package-lock.json"), diff, monkeypatch, capsys)
        assert f"missing{LOCK_SPELLED} 1.0.0 changed in" in err

    def test_a_package_installed_at_another_version(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        installed = tmp_path / "node_modules" / "other" / "package.json"
        installed.parent.mkdir(parents=True)
        installed.write_text(json.dumps({"name": "other", "version": f"9.9.9{NAME}"}))
        diff = _diff(("other", "2.0.0"))
        err = self._run(str(tmp_path / "package-lock.json"), diff, monkeypatch, capsys)
        assert f"the installed version is 9.9.9{SPELLED}" in err

    def test_the_report_names_the_package(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _named(tmp_path, f"node_modules/inst{LOCK_NAME}/index.js")
        package_json = tmp_path / "node_modules" / f"inst{LOCK_NAME}" / "package.json"
        package_json.write_text(json.dumps({"version": "3.0.0"}), encoding="utf-8")
        diff = _diff((f"inst{LOCK_NAME}", "3.0.0"))
        monkeypatch.setattr(lockfile, "get_lockfile_diff", lambda path: diff)
        main(["--no-color", "--scan-deps", "--diff-only", str(tmp_path / "package-lock.json")])
        out = capsys.readouterr().out
        assert f"pkg:inst{LOCK_SPELLED}" in out
        assert _raw(out) == []
