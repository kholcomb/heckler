"""Standard output takes every character, whatever its encoding is."""

from __future__ import annotations

import ast
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

    @pytest.mark.parametrize("json_document", [False, True])
    def test_the_handler_windows_gives_a_pipe(
        self, monkeypatch: pytest.MonkeyPatch, json_document: bool
    ) -> None:
        raw = _stdout(monkeypatch, "cp1252", errors="surrogateescape")
        value = {"file": f"{CYRILLIC}{ASTRAL}.py"}
        text = json.dumps(value, indent=2, ensure_ascii=False)
        write_out(text, json_document=json_document)
        if json_document:
            assert _written(raw) == json.dumps(value, indent=2).encode("ascii") + b"\n"
        else:
            assert _written(raw) == text.encode("ascii", "backslashreplace") + b"\n"

    def test_surrogateescape_still_writes_the_byte(self, monkeypatch: pytest.MonkeyPatch) -> None:
        raw = _stdout(monkeypatch, "utf-8", errors="surrogateescape")
        write_out(f"x{LONE_SURROGATE}.py")
        assert _written(raw) == b"x" + bytes([0x80]) + b".py\n"

    def test_an_encoding_python_does_not_know(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class Stream(io.StringIO):
            encoding = "not-a-codec"
            errors = "strict"

        stream = Stream()
        monkeypatch.setattr(sys, "stdout", stream)
        write_out(f"a {CYRILLIC} b")
        assert stream.getvalue() == f"a {CYRILLIC} b\n"


def _run(
    *args: str, encoding: str | None, annotations: bool = False
) -> subprocess.CompletedProcess[bytes]:
    """Run the command line, from the package under test, with standard output in *encoding*.

    With None, nothing is set and the process gets the stream the platform gives.
    """
    env = {k: v for k, v in os.environ.items() if k != "GITHUB_ACTIONS"}
    if encoding is None:
        env.pop("PYTHONIOENCODING", None)
        env.pop("PYTHONUTF8", None)
    else:
        env["PYTHONIOENCODING"] = encoding
    env["PYTHONPATH"] = str(Path(heckler.__file__).parent.parent)
    if annotations:
        env["GITHUB_ACTIONS"] = "true"
    command = [sys.executable, "-m", "heckler", "--no-color", *args]
    return subprocess.run(command, capture_output=True, env=env, check=False)


def _planted(directory: Path, name: str, line: str = "x = 1") -> None:
    (directory / name).write_text(f"{line}  # {chr(0x202E)}\n", encoding="utf-8")


class TestCommandLine:
    @pytest.mark.parametrize("limited", ["cp1252", "cp1252:surrogateescape"])
    def test_a_source_line_the_stream_cannot_encode(self, tmp_path: Path, limited: str) -> None:
        _planted(tmp_path, "sample.py", line=f'name = "{CYRILLIC}"')
        result = _run(str(tmp_path), encoding=limited)
        reference = _run(str(tmp_path), encoding="utf-8")
        assert result.returncode == reference.returncode == 0
        assert b"Traceback" not in result.stderr
        assert b"U+202E" in result.stdout
        assert CYRILLIC.encode("ascii", "backslashreplace") in result.stdout

    @pytest.mark.parametrize("limited", ["cp1252", "cp1252:surrogateescape"])
    @pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
    @pytest.mark.parametrize("stem", [CYRILLIC, "e" + ASTRAL])
    def test_a_file_name_the_stream_cannot_encode(
        self, tmp_path: Path, fmt: str, stem: str, limited: str
    ) -> None:
        _planted(tmp_path, f"{stem}.py")
        result = _run("--format", fmt, str(tmp_path), encoding=limited)
        reference = _run("--format", fmt, str(tmp_path), encoding="utf-8")
        assert result.returncode == reference.returncode == 0
        assert b"Traceback" not in result.stderr
        if fmt == "text":
            assert stem.encode("ascii", "backslashreplace") in result.stdout
        else:
            ours = json.loads(result.stdout.decode("cp1252"))
            assert ours == json.loads(reference.stdout.decode("utf-8"))

    @pytest.mark.parametrize("limited", ["cp1252", "cp1252:surrogateescape"])
    def test_an_annotation_names_the_file_escaped(self, tmp_path: Path, limited: str) -> None:
        _planted(tmp_path, f"{CYRILLIC}.py")
        result = _run(str(tmp_path), encoding=limited, annotations=True)
        assert result.returncode == 0
        lines = [ln for ln in result.stdout.splitlines() if ln.startswith(b"::error file=")]
        assert lines and CYRILLIC.encode("ascii", "backslashreplace") in lines[0]

    @pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
    def test_the_stream_the_platform_gives(self, tmp_path: Path, fmt: str) -> None:
        _planted(tmp_path, f"e{ASTRAL}.py", line=f'name = "{CYRILLIC}"')
        result = _run("--format", fmt, str(tmp_path), encoding=None)
        reference = _run("--format", fmt, str(tmp_path), encoding="utf-8")
        assert result.returncode == reference.returncode == 0
        assert b"Traceback" not in result.stderr
        if fmt != "text":
            assert json.loads(result.stdout.decode("utf-8")) == json.loads(reference.stdout)


def _calls(package: Path) -> list[tuple[str, str, ast.Call]]:
    """(file, enclosing function, call) for every call in the package but _output.py."""
    found: list[tuple[str, str, ast.Call]] = []
    for path in sorted(package.rglob("*.py")):
        if path.name == "_output.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for function in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            found += [
                (path.name, function.name, n) for n in ast.walk(function) if isinstance(n, ast.Call)
            ]
    return found


def _writes_to_a_stream(call: ast.Call) -> bool:
    f = call.func
    return (isinstance(f, ast.Name) and f.id == "print") or (
        isinstance(f, ast.Attribute)
        and f.attr == "write"
        and isinstance(f.value, ast.Attribute)
        and f.value.attr in ("stdout", "stderr")
    )


def test_only_the_output_module_writes_to_a_stream() -> None:
    package = Path(heckler.__file__).parent
    offenders = [f"{file}:{c.lineno}" for file, _, c in _calls(package) if _writes_to_a_stream(c)]
    assert offenders == []


def test_write_out_is_given_a_formatters_document_only() -> None:
    """Anything else goes through write_line(), which spells names out."""
    package = Path(heckler.__file__).parent
    sites = [
        (file, function, call)
        for file, function, call in _calls(package)
        if isinstance(call.func, ast.Name) and call.func.id == "write_out"
    ]
    assert {(file, function) for file, function, _ in sites} == {
        ("cli.py", "_finish"),
        ("vet.py", "vet_package"),
    }
    assert all(isinstance(c.args[0], ast.Name) and c.args[0].id == "output" for _, _, c in sites)
