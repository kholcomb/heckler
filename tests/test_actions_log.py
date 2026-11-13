"""What the GitHub Actions runner can read as a command in heckler's output.

The runner takes a line for a workflow command when it starts with ``::`` once
leading whitespace is trimmed, and has an older form that starts with ``##[``.
Under GITHUB_ACTIONS=true, heckler's own ``::error`` annotations are the only
lines of its text output that are either. Outside it, the output is unchanged.
"""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path

import pytest

from heckler._output import write_err, write_line, write_out
from heckler.characters import Severity, ThreatCategory
from heckler.cli import main
from heckler.formatters.text import _BOLD, _RESET, format_text, not_a_command, spell_out
from heckler.scanner import Finding

ZWSP = chr(0x200B)
MESSAGE = "CRITICAL: U+FE01 (Variation Selector 2) [GLASSWORM]"
# (file name, package, source line, column): each one puts :: or ##[ where the runner looks.
INPUTS = [
    ("::a::b", None, "x = 1\n", 1),
    ("  ::a", None, "x = 1\n", 1),
    ("a##[b", None, "x = 1\n", 1),
    ("a.js", "##[a", "x = 1\n", 1),
    ("a.js", None, f"::a::b{ZWSP}\n", 7),
    ("a.js", None, f"    ::a{ZWSP}\n", 8),
    ("a.js", None, f'x = "##[a{ZWSP}"\n', 10),
]


def _runner_lines(text: str) -> list[str]:
    """The lines of *text* the runner could take for a command. Stricter than the runner."""
    return [ln for ln in text.split("\n") if ln.lstrip().startswith("::") or "##[" in ln]


def _unescape(value: str, pairs: tuple[tuple[str, str], ...]) -> str:
    for escaped, raw in pairs:
        value = value.replace(escaped, raw)
    return value


_DATA = (("%0D", "\r"), ("%0A", "\n"), ("%25", "%"))
_PROPERTY = (("%0D", "\r"), ("%0A", "\n"), ("%3A", ":"), ("%2C", ","), ("%25", "%"))


def _read_annotation(line: str) -> tuple[dict[str, str], str]:
    """The properties and message of a ``::error`` line, split and unescaped as the runner does."""
    end = line.find("::", 2)
    name, _, props = line[2:end].partition(" ")
    assert name == "error"
    properties = {}
    for pair in props.split(","):
        key, _, value = pair.partition("=")
        properties[key] = _unescape(value, _PROPERTY)
    return properties, _unescape(line[end + 2 :], _DATA)


def _annotation(name: str, column: int = 1) -> str:
    file = spell_out(name).replace("%", "%25").replace(":", "%3A").replace(",", "%2C")
    return f"::error file={file},line=1,col={column}::{MESSAGE}"


def _finding(**changes: object) -> Finding:
    fields: dict[str, object] = {
        "file": "a.js",
        "line": 1,
        "column": 1,
        "codepoint": 0xFE01,
        "codepoint_hex": "U+FE01",
        "char_name": "Variation Selector 2",
        "category": ThreatCategory.VARIATION_SELECTOR,
        "severity": Severity.CRITICAL,
        "line_content": "x = 1\n",
        "source": "project",
        "package": None,
    }
    fields.update(changes)
    return Finding(**fields)  # type: ignore[arg-type]


@pytest.fixture
def actions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.delenv("FORCE_COLOR", raising=False)


@pytest.fixture
def terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)


def _report(file: str, package: str | None, content: str, column: int) -> str:
    source = "dependency" if package else "project"
    found = _finding(file=file, package=package, source=source, line_content=content, column=column)
    return format_text([found, _finding(file="sub/b.js")], color=False)


@pytest.mark.usefixtures("actions")
class TestTheAnnotation:
    @pytest.mark.parametrize("name", ["src/a::b.js", "50%,a:b.js", "a##[b"])
    def test_the_file_property_names_the_whole_file(self, name: str) -> None:
        out = format_text([_finding(file=name)], color=False, quiet=True)
        (line,) = _runner_lines(out)
        assert _read_annotation(line) == ({"file": name, "line": "1", "col": "1"}, MESSAGE)

    @pytest.mark.parametrize("char_name", ["Tag ','", "Tag ':'", "Tag '%'"])
    def test_the_message_reads_as_written(self, char_name: str) -> None:
        out = format_text([_finding(char_name=char_name)], color=False, quiet=True)
        (line,) = _runner_lines(out)
        assert _read_annotation(line)[1] == f"CRITICAL: U+FE01 ({char_name}) [GLASSWORM]"


@pytest.mark.usefixtures("actions")
class TestUnderActions:
    @pytest.mark.parametrize("file, package, content, column", INPUTS)
    def test_only_the_annotations_are_commands(
        self, file: str, package: str | None, content: str, column: int
    ) -> None:
        out = _report(file, package, content, column)
        assert _runner_lines(out) == [_annotation(file, column), _annotation("sub/b.js")]

    def test_the_lines_still_read(self) -> None:
        assert "<U+003A>:a::b" in _report("::a::b", None, "x = 1\n", 1).split("\n")
        assert "  <U+003A>:a" in _report("  ::a", None, "x = 1\n", 1).split("\n")
        assert "a<U+0023>#[b" in _report("a##[b", None, "x = 1\n", 1).split("\n")
        assert "pkg:<U+0023>#[a" in _report("a.js", "##[a", "x = 1\n", 1)
        excerpt = _report("a.js", None, f"::a::b{ZWSP}\n", 7)
        assert "      <U+003A>:a::b<U+200B>" in excerpt.split("\n")

    def test_a_colon_pair_inside_a_line_stays(self) -> None:
        assert "a::b.js" in _report("a::b.js", None, "x = 1\n", 1).split("\n")

    def test_the_header_is_written_before_its_colour(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("FORCE_COLOR", "1")
        out = format_text([_finding(file="::a")], color=True)
        assert f"{_BOLD}<U+003A>:a{_RESET}" in out.split("\n")

    def test_messages_are_not_commands(self, capsys: pytest.CaptureFixture[str]) -> None:
        write_err("::a::b: not scanned")
        write_line("  ::a")
        write_line("Warning: ##[a was not scanned")
        out, err = capsys.readouterr()
        assert _runner_lines(out) == _runner_lines(err) == []
        assert err == "<U+003A>:a::b: not scanned\n"
        assert out == "  <U+003A>:a\nWarning: <U+0023>#[a was not scanned\n"

    def test_written_twice_is_written_once(self) -> None:
        for line in ("::a::b", "  ::a", "a##[b", "###[a", "::##[a"):
            once = not_a_command(line)
            assert not_a_command(once) == once
            assert _runner_lines(once) == []


@pytest.mark.usefixtures("terminal")
class TestOutsideActions:
    @pytest.mark.parametrize("file, package, content, column", INPUTS)
    def test_the_report_is_unchanged(
        self, file: str, package: str | None, content: str, column: int
    ) -> None:
        out = _report(file, package, content, column)
        assert "<U+003A>" not in out
        assert "<U+0023>" not in out
        assert "::error" not in out

    def test_messages_are_unchanged(self, capsys: pytest.CaptureFixture[str]) -> None:
        write_err("::a")
        write_line("##[a")
        assert capsys.readouterr() == ("##[a\n", "::a\n")


def _stdout(monkeypatch: pytest.MonkeyPatch, errors: str) -> io.BytesIO:
    """Put an ASCII byte stream with the error handler *errors* in place of standard output."""
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="ascii", errors=errors, newline="")
    monkeypatch.setattr(sys, "stdout", stream)
    return raw


def _written(raw: io.BytesIO) -> str:
    sys.stdout.flush()
    return raw.getvalue().decode("ascii")


ZHE = chr(0x416)  # an ASCII stream cannot take it
FIRST = f":{ZHE}:x.js"  # with the ZHE dropped, it reads ::x.js
SECOND = f"ok\n      #{ZHE}#[y"  # with the ZHE dropped, the second line holds ##[


class TestAStreamThatDropsCharacters:
    @pytest.mark.usefixtures("actions")
    def test_a_dropped_character_does_not_make_a_command(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        raw = _stdout(monkeypatch, "ignore")
        write_line(FIRST)
        out = _written(raw)
        assert not out.startswith("::")
        assert out == ":\\u0416:x.js\n"

    @pytest.mark.usefixtures("actions")
    def test_a_dropped_character_does_not_make_the_old_form(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        raw = _stdout(monkeypatch, "ignore")
        write_out(SECOND)
        out = _written(raw)
        assert not any("##[" in line for line in out.split("\n"))
        assert out == "ok\n      #\\u0416#[y\n"

    @pytest.mark.usefixtures("terminal")
    def test_outside_actions_the_character_is_dropped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        raw = _stdout(monkeypatch, "ignore")
        write_line(FIRST)
        assert _written(raw) == "::x.js\n"

    @pytest.mark.usefixtures("actions")
    def test_a_json_document_is_written_as_before(self, monkeypatch: pytest.MonkeyPatch) -> None:
        raw = _stdout(monkeypatch, "ignore")
        write_out(json.dumps({"file": ZHE}, ensure_ascii=False), json_document=True)
        assert _written(raw) == '{"file": ""}\n'

    @pytest.mark.usefixtures("actions")
    def test_a_replacing_stream_is_written_as_before(self, monkeypatch: pytest.MonkeyPatch) -> None:
        raw = _stdout(monkeypatch, "replace")
        write_line(FIRST)
        assert _written(raw) == ":?:x.js\n"


@pytest.mark.skipif(sys.platform == "win32", reason="on NTFS a colon in a name names a stream")
@pytest.mark.usefixtures("actions")
def test_a_scan_of_a_tree_under_actions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    names = ["::a::b", "a##[b/c.js", "sub/b.js"]
    for name in names:
        path = tmp_path / name
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"x = 1  # {ZWSP}\n", encoding="utf-8")
        except OSError:
            pytest.skip("this filesystem does not take such a name")
        if path.name not in os.listdir(path.parent):
            pytest.skip("this filesystem does not take such a name")
    monkeypatch.chdir(tmp_path)
    assert main(["--no-color", "--ci", "--severity", "low", "."]) == 1
    out, err = capsys.readouterr()
    files = sorted(_read_annotation(line)[0]["file"] for line in _runner_lines(out))
    assert files == sorted(names)
    assert _runner_lines(err) == []
