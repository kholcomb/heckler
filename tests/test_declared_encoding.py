"""A file that declares its source encoding is read in that encoding as well.

A comment on the first or second line of a file can name the encoding the
file is in, and the interpreter then reads the file in it. The characters a
scan is for are checked in that reading too, so that bytes which mean nothing
as UTF-8 cannot hide what they mean in the encoding the file declares.
"""

import base64
import codecs
import io
import json
import tarfile
from pathlib import Path

import pytest

from heckler import lockfile, vet
from heckler.cli import main
from heckler.scanner import Scanner

RLO, RLM, NEL, NBSP = chr(0x202E), chr(0x200F), chr(0x85), chr(0xA0)
BODY = "x = 'a{}b'\n"


def _declaring(
    codec: str, body: str, *, first: str = "", form: str = "# -*- coding: {} -*-"
) -> bytes:
    """A file whose first or second line declares *codec*, and whose *body* is in it."""
    return (first + form.format(codec) + "\n").encode("ascii") + body.encode(codec)


def _label(codec: str) -> str:
    return f"(read as {codecs.lookup(codec).name.upper()}, as declared)"


def _names(path: Path, **options: object) -> list[str]:
    return [f.char_name for f in Scanner(**options).scan_file(path)]  # type: ignore[arg-type]


def _name_of(char: str) -> str:
    """The name the scanner gives *char* in an undeclared UTF-8 file."""
    (finding,) = Scanner().scan_text(char)
    return finding.char_name


def _write(tmp_path: Path, data: bytes, name: str = "sample.py") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


class TestADeclaredEncodingIsRead:
    def test_on_the_first_line(self, tmp_path: Path) -> None:
        path = _write(tmp_path, _declaring("gb18030", BODY.format(RLO)))
        assert _names(path) == [f"Right-to-Left Override {_label('gb18030')}"]

    def test_on_the_second_line(self, tmp_path: Path) -> None:
        raw = _declaring("gb18030", BODY.format(RLO), first="#!/bin/sh\n")
        path = _write(tmp_path, raw)
        assert _names(path) == [f"Right-to-Left Override {_label('gb18030')}"]

    def test_not_on_the_third_line(self, tmp_path: Path) -> None:
        path = _write(tmp_path, _declaring("gb18030", BODY.format(RLO), first="#\n#\n"))
        assert _names(path) == []

    def test_lines_that_end_at_a_lone_cr(self, tmp_path: Path) -> None:
        raw = _declaring("gb18030", BODY.format(RLO)).replace(b"\n", b"\r")
        path = _write(tmp_path, raw)
        assert _names(path) == [f"Right-to-Left Override {_label('gb18030')}"]

    def test_bytes_after_the_declaration_on_its_line(self, tmp_path: Path) -> None:
        raw = (
            b"# coding: gb18030 "
            + chr(0x4E2D).encode("gb18030")
            + b"\n"
            + BODY.format(RLO).encode("gb18030")
        )
        path = _write(tmp_path, raw)
        assert _names(path) == [f"Right-to-Left Override {_label('gb18030')}"]

    @pytest.mark.parametrize("form", ["# coding={}", "#coding:{}", "# vim: set fileencoding={} :"])
    def test_every_form_of_the_declaration(self, tmp_path: Path, form: str) -> None:
        path = _write(tmp_path, _declaring("gb18030", BODY.format(RLO), form=form))
        assert _names(path) == [f"Right-to-Left Override {_label('gb18030')}"]

    @pytest.mark.parametrize(
        ("codec", "char"),
        [
            ("cp1255", RLM),
            ("latin-1", NEL),
            ("cp949", chr(0x3164)),
            ("utf-7", RLO),
            ("raw_unicode_escape", RLO),
        ],
    )
    def test_each_kind_of_encoding(self, tmp_path: Path, codec: str, char: str) -> None:
        path = _write(tmp_path, _declaring(codec, BODY.format(char)))
        assert f"{_name_of(char)} {_label(codec)}" in _names(path)


class TestWhatIsNotReadAgain:
    @pytest.mark.parametrize("codec", ["utf-8", "utf8", "UTF_8", "utf-8-sig", "utf-8-unix"])
    def test_utf8_under_any_of_its_names(self, tmp_path: Path, codec: str) -> None:
        body = BODY.format(RLO).encode("utf-8")
        declared = _write(tmp_path, f"# coding: {codec}\n".encode("ascii") + body, "declared.py")
        plain = _write(tmp_path, b"# comment\n" + body, "plain.py")
        names = _names(declared)
        assert names == _names(plain)
        assert not any("as declared" in name for name in names)

    def test_ascii_under_a_legacy_declaration(self, tmp_path: Path) -> None:
        path = _write(tmp_path, _declaring("latin-1", "plain\n"))
        assert _names(path) == []

    def test_a_character_the_first_reading_reported_is_not_reported_twice(
        self, tmp_path: Path
    ) -> None:
        # The last line makes the two readings differ. Without it there is no
        # declared reading, and the test proves nothing.
        raw = _declaring("latin-1", BODY.format(chr(1)) + chr(0xE9) + "\n")
        names = _names(_write(tmp_path, raw))
        assert names == [_name_of(chr(1))]

    def test_a_character_on_another_line_is_not_taken_for_a_duplicate(self, tmp_path: Path) -> None:
        # UTF-7 reads this ASCII as a line break and then U+202E, so the lines
        # that follow are numbered differently in the two readings.
        shifted = b"+" + base64.b64encode((chr(10) + chr(0x202E)).encode("utf-16-be")).rstrip(b"=")
        raw = (
            b"# coding: utf-7\n"
            + b's = "'
            + shifted
            + b'-"\n'
            + b"y = '"
            + chr(0x202E).encode("utf-8")
            + b"'  # heckler-ignore U+202E\n"
        )
        scanner = Scanner()
        path = _write(tmp_path, raw)
        names = [f.char_name for f in scanner.scan_file(path)]
        assert names.count(f"Right-to-Left Override {_label('utf-7')}") == 1
        assert scanner.suppressed == {str(path): 1}

    def test_a_suppressed_character_does_not_cover_another_on_a_line_that_reads_differently(
        self, tmp_path: Path
    ) -> None:
        raw = (
            b"# coding: gb18030\n"
            + b"x = '"
            + chr(0x202E).encode("utf-8")
            + b"' '"
            + chr(0x202E).encode("gb18030")
            + b"'  # heckler-ignore U+202E\n"
        )
        scanner = Scanner()
        path = _write(tmp_path, raw)
        names = [f.char_name for f in scanner.scan_file(path)]
        assert names == [f"Right-to-Left Override {_label('gb18030')}"]
        assert scanner.suppressed == {str(path): 1}

    @pytest.mark.parametrize("codec", ["rot13", "base64", "utf-16", "cp037"])
    def test_an_encoding_python_refuses_for_source(self, tmp_path: Path, codec: str) -> None:
        raw = f"# coding: {codec}\n".encode("ascii") + BODY.format(NEL).encode("latin-1")
        path = _write(tmp_path, raw)
        scanner = Scanner()
        names = [f.char_name for f in scanner.scan_file(path)]
        assert not any("as declared" in name for name in names)
        assert scanner.skipped == []


class TestALegacyFile:
    def test_with_nothing_to_flag_is_clean(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = _write(tmp_path, _declaring("latin-1", BODY.format(chr(0xE9))))
        assert main(["--ci", str(path)]) == 0
        assert capsys.readouterr().err == ""

    def test_utf8_text_under_a_stale_declaration(self, tmp_path: Path) -> None:
        # The right single quotation mark is E2 80 99 in UTF-8, and in the
        # declared reading the last two of those bytes are C1 controls.
        raw = _declaring("latin-1", "") + BODY.format(chr(0x2019)).encode("utf-8")
        names = _names(_write(tmp_path, raw))
        for char in (chr(0x80), chr(0x99)):
            assert f"{_name_of(char)} {_label('latin-1')}" in names


class TestADeclarationHecklerCannotRead:
    def test_an_unknown_name_in_bytes_that_are_not_utf8(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = _write(tmp_path, b"# coding: no-such-codec\n" + NEL.encode("latin-1") + b"\n")
        assert main(["--ci", str(path)]) == 2
        err = capsys.readouterr().err
        assert (
            "was not scanned: it declares an encoding this Python does not know (no-such-codec)"
            in err
        )
        assert main(["--ci", "--allow-unscanned", str(path)]) == 0

    def test_an_unknown_name_in_utf8_is_not_an_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = _write(tmp_path, b"# Encoding: overview\ntext\n")
        assert main(["--ci", str(path)]) == 0
        assert capsys.readouterr().err == ""

    def test_bytes_the_codec_cannot_decode(self, tmp_path: Path) -> None:
        raw = _declaring("gb18030", BODY.format(RLO)) + b"\x81\x20\n"
        scanner = Scanner()
        names = [f.char_name for f in scanner.scan_file(_write(tmp_path, raw))]
        assert f"Right-to-Left Override {_label('gb18030')}" in names
        assert scanner.skipped == []


class TestFindingsCap:
    def test_the_declared_reading_stops_at_10000(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = _write(tmp_path, _declaring("latin-1", NEL * 10_050 + "\n"))
        assert len(Scanner().scan_file(path)) == 10_000
        assert capsys.readouterr().err.count("stopped after 10000 findings") == 1

    def test_a_first_reading_that_stopped_does_not_stop_the_declared_one(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = _write(tmp_path, _declaring("cp1255", chr(1) * 10_050 + "\n" + BODY.format(RLM)))
        names = _names(path)
        assert f"{_name_of(RLM)} {_label('cp1255')}" in names
        assert capsys.readouterr().err.count("stopped after 10000 findings") == 1


class TestDirectivesInTheDeclaredReading:
    def test_on_a_line_that_reads_the_same(self, tmp_path: Path) -> None:
        raw = _declaring("latin-1", "# heckler-ignore-next-line U+00A0\n" + BODY.format(NBSP))
        scanner = Scanner()
        path = _write(tmp_path, raw)
        assert scanner.scan_file(path) == []
        assert scanner.suppressed == {str(path): 1}

    def test_not_one_that_only_the_declared_reading_holds(self, tmp_path: Path) -> None:
        # UTF-7 reads the first line below as a directive; as UTF-8 it is
        # plain ASCII that no reviewer of the file would take for one.
        directive = (
            b"+"
            + base64.b64encode("#".encode("utf-16-be")).rstrip(b"=")
            + b"- heckler-ignore-next-line U+-202E\n"
        )
        # The fixture itself: UTF-7 reads "+-" as a plus sign, so the line is a
        # directive there, and it is not one as UTF-8.
        assert directive.decode("utf-7") == "# heckler-ignore-next-line U+202E\n"
        assert not directive.decode("utf-8").startswith("#")
        raw = _declaring("utf-7", "") + directive + BODY.format(RLO).encode("utf-7")
        names = _names(_write(tmp_path, raw))
        assert f"Right-to-Left Override {_label('utf-7')}" in names

    def test_not_counted_twice(self, tmp_path: Path) -> None:
        # The last line makes the two readings differ.
        raw = _declaring("latin-1", "a" + chr(1) + "b # heckler-ignore U+0001\n" + chr(0xE9) + "\n")
        scanner = Scanner()
        path = _write(tmp_path, raw)
        assert scanner.scan_file(path) == []
        assert scanner.suppressed == {str(path): 1}

    def test_never_in_dependency_code(self, tmp_path: Path) -> None:
        raw = _declaring("latin-1", "# heckler-ignore-next-line U+00A0\n" + BODY.format(NBSP))
        (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
        _write(tmp_path / "node_modules" / "pkg", raw, "index.js")
        names = [f.char_name for f in Scanner(scan_deps=True).scan_path(tmp_path)]
        assert f"{_name_of(NBSP)} {_label('latin-1')}" in names


SAMPLE = _declaring("gb18030", BODY.format(RLO))


def _tar_gz(path: Path, files: dict[str, bytes]) -> Path:
    with tarfile.open(path, "w:gz") as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return path


def _diff(*packages: tuple[str, str]) -> str:
    lines = ["+{", '+  "lockfileVersion": 3,', '+  "packages": {']
    for name, version in packages:
        lines += [f'+    "node_modules/{name}": {{', f'+      "version": "{version}"', "+    },"]
    lines += ["+  }", "+}"]
    return "\n".join(lines) + "\n"


class TestEveryWayIn:
    @pytest.mark.parametrize("name", ["tool.py", "tool"])
    def test_a_walk(self, tmp_path: Path, name: str) -> None:
        _write(tmp_path, SAMPLE, name)
        names = [f.char_name for f in Scanner().scan_path(tmp_path)]
        assert f"Right-to-Left Override {_label('gb18030')}" in names

    def test_a_file_passed_by_name(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = _write(tmp_path, SAMPLE)
        assert main(["--ci", str(path)]) == 1
        assert "as declared" in capsys.readouterr().out

    def test_the_pre_commit_hook(self, tmp_path: Path) -> None:
        path = _write(tmp_path, SAMPLE)
        assert main(["--ci", "--skip-binary", str(path)]) == 1

    def test_a_file_that_looks_binary(self, tmp_path: Path) -> None:
        padding = b"# coding: gb18030\n# " + (chr(1) * 400).encode("ascii") + b"\n"
        directive = b"# heckler-ignore-next-line U+202E\n"
        body = BODY.format(RLO).encode("gb18030")
        _write(tmp_path, padding + body, "tool")
        scanner = Scanner()
        findings = scanner.scan_path(tmp_path)
        assert f"Right-to-Left Override {_label('gb18030')}" in [f.char_name for f in findings]
        assert str(tmp_path / "tool") in scanner.binary
        assert not any(f.codepoint < 0x20 for f in findings)

        # A directive in a file like this suppresses nothing.
        _write(tmp_path, padding + directive + body, "tool")
        scanner = Scanner()
        names = [f.char_name for f in scanner.scan_path(tmp_path)]
        assert f"Right-to-Left Override {_label('gb18030')}" in names

    def test_vet(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        archive = _tar_gz(tmp_path / "pkg-1.0.tar.gz", {"pkg-1.0/tool.py": SAMPLE})

        def fake(
            spec: str,
            registry: str,
            tmpdir: str,
            not_scanned: list[tuple[str, str]] | None = None,
        ) -> list[Path]:
            return [archive]

        monkeypatch.setattr(vet, "download_package", fake)
        assert main(["--no-color", "--registry", "pypi", "--vet", "pkg==1.0"]) == 1
        assert "as declared" in capsys.readouterr().out

    def test_diff_only(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
        _write(tmp_path / "node_modules" / "pkg", SAMPLE, "index.js")
        (tmp_path / "node_modules" / "pkg" / "package.json").write_text(
            json.dumps({"version": "1.0.0"}), encoding="utf-8"
        )
        diff = _diff(("pkg", "1.0.0"))
        monkeypatch.setattr(lockfile, "get_lockfile_diff", lambda path: diff)
        args = ["--ci", "--no-color", "--scan-deps", "--diff-only"]
        assert main([*args, str(tmp_path / "package-lock.json")]) == 1
        assert "as declared" in capsys.readouterr().out
