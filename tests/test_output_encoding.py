"""Standard output takes every character, whatever its encoding is."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import heckler
from heckler._output import write_out

CYRILLIC = chr(0x444) + chr(0x430)  # neither has a decomposition
ASTRAL = chr(0x1F600)
DASH = chr(0x2014)  # cp1252 has it
E_ACUTE = chr(0xE9)  # cp1252 has it
LONE_SURROGATE = chr(0xDC80)  # what a file name that is not UTF-8 decodes to


def _stdout(monkeypatch: pytest.MonkeyPatch, encoding: str, errors: str = "strict") -> io.BytesIO:
    """Put a byte stream in place of standard output. newline="" is for Windows."""
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding=encoding, errors=errors, newline="")
    monkeypatch.setattr(sys, "stdout", stream)
    return raw


def _written(raw: io.BytesIO) -> bytes:
    sys.stdout.flush()
    return raw.getvalue()


class TestWriteOut:
    def test_text_gets_backslash_escapes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        raw = _stdout(monkeypatch, "cp1252")
        text = f"a {CYRILLIC} b {ASTRAL}"
        write_out(text)
        assert _written(raw) == text.encode("ascii", "backslashreplace") + b"\n"

    def test_what_the_stream_can_encode_is_untouched(self, monkeypatch: pytest.MonkeyPatch) -> None:
        raw = _stdout(monkeypatch, "cp1252")
        text = f"[VET] pkg {DASH} caf{E_ACUTE}"
        write_out(text)
        assert _written(raw) == text.encode("cp1252") + b"\n"

    @pytest.mark.parametrize("json_document", [False, True])
    def test_utf8_is_untouched(self, monkeypatch: pytest.MonkeyPatch, json_document: bool) -> None:
        raw = _stdout(monkeypatch, "utf-8")
        text = json.dumps({"file": CYRILLIC + ASTRAL}, indent=2, ensure_ascii=False)
        write_out(text, json_document=json_document)
        assert _written(raw) == text.encode("utf-8") + b"\n"

    def test_json_gets_json_escapes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        raw = _stdout(monkeypatch, "cp1252")
        value = {"file": f"{CYRILLIC}{ASTRAL}.py", "name": f"caf{E_ACUTE}"}
        write_out(json.dumps(value, indent=2, ensure_ascii=False), json_document=True)
        assert _written(raw) == json.dumps(value, indent=2).encode("ascii") + b"\n"

    def test_a_lenient_stream_is_left_alone(self, monkeypatch: pytest.MonkeyPatch) -> None:
        raw = _stdout(monkeypatch, "cp1252", errors="replace")
        write_out(f"a {CYRILLIC} b")
        assert _written(raw) == b"a ?? b\n"

    def test_a_stream_with_no_encoding(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stream = io.StringIO()
        monkeypatch.setattr(sys, "stdout", stream)
        write_out(f"a {CYRILLIC} b")
        assert stream.getvalue() == f"a {CYRILLIC} b\n"

    @pytest.mark.parametrize("json_document", [False, True])
    def test_a_lone_surrogate_on_utf8(
        self, monkeypatch: pytest.MonkeyPatch, json_document: bool
    ) -> None:
        raw = _stdout(monkeypatch, "utf-8")
        value = {"file": f"x{LONE_SURROGATE}.py"}
        text = json.dumps(value, ensure_ascii=False)
        write_out(text, json_document=json_document)
        if json_document:
            assert json.loads(_written(raw)) == value
        else:
            assert _written(raw) == text.encode("ascii", "backslashreplace") + b"\n"


def _run(
    *args: str, encoding: str, annotations: bool = False
) -> subprocess.CompletedProcess[bytes]:
    """Run the command line, from the package under test, with standard output in *encoding*."""
    env = {k: v for k, v in os.environ.items() if k != "GITHUB_ACTIONS"}
    env["PYTHONIOENCODING"] = encoding
    env["PYTHONPATH"] = str(Path(heckler.__file__).parent.parent)
    if annotations:
        env["GITHUB_ACTIONS"] = "true"
    command = [sys.executable, "-m", "heckler", "--no-color", *args]
    return subprocess.run(command, capture_output=True, env=env, check=False)


def _planted(directory: Path, name: str, line: str = "x = 1") -> None:
    (directory / name).write_text(f"{line}  # {chr(0x202E)}\n", encoding="utf-8")


class TestCommandLine:
    def test_a_source_line_the_stream_cannot_encode(self, tmp_path: Path) -> None:
        _planted(tmp_path, "sample.py", line=f'name = "{CYRILLIC}"')
        result = _run(str(tmp_path), encoding="cp1252")
        assert result.returncode == _run(str(tmp_path), encoding="utf-8").returncode == 0
        assert b"Traceback" not in result.stderr
        assert b"U+202E" in result.stdout
        assert CYRILLIC.encode("ascii", "backslashreplace") in result.stdout

    @pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
    @pytest.mark.parametrize("stem", [CYRILLIC, "e" + ASTRAL])
    def test_a_file_name_the_stream_cannot_encode(
        self, tmp_path: Path, fmt: str, stem: str
    ) -> None:
        _planted(tmp_path, f"{stem}.py")
        result = _run("--format", fmt, str(tmp_path), encoding="cp1252")
        reference = _run("--format", fmt, str(tmp_path), encoding="utf-8")
        assert result.returncode == reference.returncode == 0
        assert b"Traceback" not in result.stderr
        if fmt == "text":
            assert stem.encode("ascii", "backslashreplace") in result.stdout
        else:
            ours = json.loads(result.stdout.decode("cp1252"))
            assert ours == json.loads(reference.stdout.decode("utf-8"))

    def test_an_annotation_names_the_file_escaped(self, tmp_path: Path) -> None:
        _planted(tmp_path, f"{CYRILLIC}.py")
        result = _run(str(tmp_path), encoding="cp1252", annotations=True)
        assert result.returncode == 0
        lines = [ln for ln in result.stdout.splitlines() if ln.startswith(b"::error file=")]
        assert lines and CYRILLIC.encode("ascii", "backslashreplace") in lines[0]
