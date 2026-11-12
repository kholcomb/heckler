"""A file that is mostly text is scanned, whatever its first bytes look like.

Whether a file looks binary is decided by the start of it, and whoever wrote
the file wrote those bytes. So a file that looks binary is read in full
before it is left out. When no more than a quarter of it is control bytes
and invalid UTF-8, it is mostly text: every stretch of 32 characters or more
that decodes as UTF-8 is scanned, without control characters and without
suppression directives. A file that is more than a quarter junk is binary,
and is left out. Either way the file is named in the report, as every file
that looks binary was before: that reading leaves things out.

Everything is built with chr(), so this file holds none of the characters,
and the samples are inert: text in a comment or a string, read by nothing.
"""

from __future__ import annotations

import random
import zlib
from pathlib import Path

import pytest

from heckler import scanner as scanner_module
from heckler.cli import main
from heckler.scanner import Scanner

RLO = chr(0x202E)
ZWSP = chr(0x200B)
LOOKS_BINARY = " (in a file that looks binary)"

# Bytes that are not UTF-8, so they end a stretch of text.
INVALID = b"\xff\xfe"

# A first line with enough control bytes in it for a file to look binary.
HEAD = b"# " + b"\x01" * 300 + b"\n"

# Ordinary text, and enough of it that the 300 control bytes of HEAD are far
# less than a quarter of a file that holds both.
FILLER = b"a plain line of text, nothing to see\n" * 50


def _padded(pad: bytes) -> bytes:
    """Comment lines with enough of *pad* in the first of them to look binary.

    The flagged character sits in a string on the last line. Nothing here is
    code that does anything, and nothing reads the file but the scanner.
    """
    return (
        b"# helpers "
        + pad * 260
        + b"\n"
        + b"# one more plain line\n" * 80
        + f'greeting="a{RLO}b"\n'.encode()
    )


def _looks_binary(path: Path, content: bytes) -> Path:
    """Write a sample, and make sure it is one that the start of the file calls binary."""
    path.write_bytes(content)
    assert Scanner._is_binary(path)
    return path


class TestPaddingDoesNotOptAFileOut:
    """Control bytes near the top of a file used to take all of it out of a walk.

    260 of them in a comment made a text file without an extension binary,
    and the run ended in "No dangerous invisible Unicode characters found".
    Where the padding is U+0001, git still shows the file as text, so a
    reviewer read what heckler never looked at.
    """

    @pytest.mark.parametrize("pad", [b"\x01", b"\x00"], ids=["U+0001", "NUL"])
    @pytest.mark.parametrize("name", ["functions", "settings.inc"])
    def test_character_after_the_padding_is_reported(
        self, tmp_path: Path, pad: bytes, name: str
    ) -> None:
        _looks_binary(tmp_path / name, _padded(pad))
        scanner = Scanner()
        findings = scanner.scan_path(tmp_path)
        assert [(f.line, f.column, f.char_name) for f in findings] == [
            (82, 12, "Right-to-Left Override" + LOOKS_BINARY)
        ]
        assert scanner.binary == [str(tmp_path / name)]
        assert scanner.skipped == []

    def test_cli_fails_the_run(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        padded = _looks_binary(tmp_path / "functions", _padded(b"\x01"))
        assert main(["--ci", "--no-color", str(tmp_path)]) == 1
        captured = capsys.readouterr()
        assert "82:12  CRITICAL  U+202E (Right-to-Left Override" + LOOKS_BINARY + ")" in (
            captured.out
        )
        assert 'greeting="a<U+202E>b"' in captured.out
        assert f"Note: not scanned as text, binary by content: {padded}." in captured.err

    def test_control_characters_are_not_reported(self, tmp_path: Path) -> None:
        """Padding is made of them, and so is what real binaries hold in between text."""
        _looks_binary(tmp_path / "functions", _padded(b"\x00\x01\x7f"))
        assert [f.codepoint for f in Scanner().scan_path(tmp_path)] == [0x202E]

    def test_control_bytes_do_not_split_the_text(self, tmp_path: Path) -> None:
        """A NUL on each side of a character is as invisible as the character.

        If control bytes ended a stretch of text, two of them would cut any
        character out of it at no cost to the attack. The invalid byte at
        the start is there so that the file is not one stretch of text from
        end to end, which is scanned whatever its length.
        """
        body = b"\xff" + HEAD + FILLER + b"# a\x00" + ZWSP.encode() + b"\x01b\n"
        _looks_binary(tmp_path / "notes", body)
        names = [f.char_name for f in Scanner().scan_path(tmp_path)]
        assert names == ["Zero Width Space" + LOOKS_BINARY]

    def test_same_bytes_under_a_name_that_marks_them_as_source(self, tmp_path: Path) -> None:
        """Read as text, as before: the padding is reported too."""
        (tmp_path / "functions.sh").write_bytes(_padded(b"\x01"))
        names = {f.char_name for f in Scanner().scan_path(tmp_path)}
        assert {"Control Character U+0001", "Right-to-Left Override"} <= names


class TestMoreThanAQuarterIsNotText:
    """The limit of the reading: a file that is mostly junk is binary, and left out.

    It is recorded and named, as every file left out as binary is. So hiding
    a character this way takes junk on the scale of the file itself, more
    than a quarter of it, and the report then lists the file by name.
    """

    def _sample(self, junk: int, size: int = 1000) -> bytes:
        """*junk* control bytes in *size* bytes, the rest text with a flagged character."""
        text = f'greeting="a{RLO}b"\n'.encode()
        return b"\x01" * junk + b"\n" + b"x" * (size - junk - 1 - len(text)) + text

    def test_a_quarter_is_still_mostly_text(self, tmp_path: Path) -> None:
        sample = self._sample(250)
        assert len(sample) == 1000
        blob = _looks_binary(tmp_path / "blob", sample)
        scanner = Scanner()
        assert [f.codepoint for f in scanner.scan_path(tmp_path)] == [0x202E]
        assert scanner.binary == [str(blob)], "named, and scanned as well"

    def test_one_byte_more_is_binary(self, tmp_path: Path) -> None:
        sample = self._sample(251)
        assert len(sample) == 1000
        blob = _looks_binary(tmp_path / "blob", sample)
        scanner = Scanner()
        assert scanner.scan_path(tmp_path) == []
        assert scanner.binary == [str(blob)]
        assert scanner.skipped == []

    def test_invalid_utf8_counts_like_control_bytes(self, tmp_path: Path) -> None:
        text = b"x" * 700 + f'greeting="a{RLO}b"\n'.encode()
        blob = _looks_binary(tmp_path / "blob", b"\x01" * 100 + b"\xff" * 200 + text)
        scanner = Scanner()
        assert scanner.scan_path(tmp_path) == []
        assert scanner.binary == [str(blob)]

    def test_mostly_junk_with_a_long_run_of_text_is_left_out_and_named(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Text inside a real binary is not scanned, however long the run it sits in."""
        text = ("a line of text that would count as a run\n" * 20 + f'x = "a{RLO}b"\n').encode()
        blob = _looks_binary(tmp_path / "blob", b"\x01\x02\x03\x04" * 1000 + text)
        scanner = Scanner()
        assert scanner.scan_path(tmp_path) == []
        assert scanner.binary == [str(blob)]

        assert main(["--ci", str(tmp_path)]) == 0
        assert f"Note: not scanned as text, binary by content: {blob}." in capsys.readouterr().err


class TestRealBinaries:
    """Data that holds no text is left out and named, as it always was."""

    def _left_out(self, root: Path, blob: Path) -> None:
        scanner = Scanner()
        assert scanner.scan_path(root) == []
        assert scanner.binary == [str(blob)]
        assert scanner.skipped == []

    def test_random_bytes(self, tmp_path: Path) -> None:
        blob = tmp_path / "blob"
        blob.write_bytes(random.Random(20261111).randbytes(4 * 1024 * 1024))
        self._left_out(tmp_path, blob)

    def test_compressed_data(self, tmp_path: Path) -> None:
        rng = random.Random(20261111)
        lines = "".join(f"{number:08x} {rng.random()}\n" for number in range(120_000))
        data = zlib.compress(lines.encode())
        assert len(data) > 512 * 1024
        blob = tmp_path / "blob.z"
        blob.write_bytes(data)
        self._left_out(tmp_path, blob)

    def test_nothing_but_zeros(self, tmp_path: Path) -> None:
        blob = tmp_path / "blob"
        blob.write_bytes(b"\x00" * (1024 * 1024))
        self._left_out(tmp_path, blob)

    def test_image_header_in_front_of_a_few_flagged_bytes(self, tmp_path: Path) -> None:
        blob = tmp_path / "logo.png"
        data = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 16 + chr(0xA0).encode() * 10
        blob.write_bytes(data)
        self._left_out(tmp_path, blob)


class TestEveryFileThatLooksBinaryIsNamed:
    """A file that looks binary is named in the report, mostly text or not.

    Reading a file that is mostly text leaves things out: every control
    character, and any stretch of fewer than 32 characters between bytes
    that are not UTF-8. Either can hold what a scan is for, at a cost far
    below the quarter. So the file is named whether or not anything was
    reported from it, as it was before such a file was read at all, and a
    file made to look binary never leaves a run without a trace.
    """

    def _cut_short(self) -> bytes:
        """Comment lines of 31 characters, with a byte that is not UTF-8 before each."""
        line = ("# " + "x" * 27 + ZWSP + "\n").encode()
        return HEAD + FILLER + (b"\xff" + line) * 40

    def test_characters_cut_into_short_stretches(self, tmp_path: Path) -> None:
        """40 invalid bytes, under 2% of the file, keep 40 characters out of every run."""
        blob = _looks_binary(tmp_path / "notes", self._cut_short())
        scanner = Scanner()
        assert scanner.scan_path(tmp_path) == []
        assert scanner.binary == [str(blob)]
        assert scanner.skipped == []

    def test_control_characters_that_are_not_reported(self, tmp_path: Path) -> None:
        """Escape sequences, backspace, DEL and a C1 control, in a comment."""
        controls = chr(0x1B) + "[2K" + chr(0x08) + chr(0x7F) + chr(0x85)
        body = HEAD + FILLER + f"# {controls}\n".encode() * 10
        blob = _looks_binary(tmp_path / "notes", body)
        scanner = Scanner()
        assert scanner.scan_path(tmp_path) == []
        assert scanner.binary == [str(blob)]

    def test_named_with_nothing_left_out_of_the_reading(self, tmp_path: Path) -> None:
        blob = _looks_binary(tmp_path / "notes", HEAD + FILLER)
        scanner = Scanner()
        assert scanner.scan_path(tmp_path) == []
        assert scanner.binary == [str(blob)]

    def test_cli_names_a_file_it_reported_nothing_from(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        blob = _looks_binary(tmp_path / "notes", self._cut_short())
        assert main(["--ci", str(tmp_path)]) == 0
        assert f"Note: not scanned as text, binary by content: {blob}." in capsys.readouterr().err


class TestTextRuns:
    """What counts as text inside a file that is read this way."""

    def _between_invalid_bytes(self, text: str) -> bytes:
        """*text* on a line of its own, with bytes that are not UTF-8 on both sides of it."""
        return HEAD + FILLER + INVALID + text.encode() + INVALID + b"\n" + FILLER

    def test_32_characters_between_invalid_bytes_are_scanned(self, tmp_path: Path) -> None:
        _looks_binary(tmp_path / "blob", self._between_invalid_bytes("x" * 31 + ZWSP))
        findings = Scanner().scan_path(tmp_path)
        assert [(f.line, f.column, f.char_name) for f in findings] == [
            (52, 2 + 32, "Zero Width Space" + LOOKS_BINARY)
        ]

    def test_31_characters_between_invalid_bytes_are_not(self, tmp_path: Path) -> None:
        """Short of 32 characters, what sits between two invalid bytes is not text.

        Without a length, bytes that only happen to be valid UTF-8 would be
        reported for the code points they spell. The character is not
        reported, then, and what stands in for that is the name of the file
        in the report.
        """
        blob = _looks_binary(tmp_path / "blob", self._between_invalid_bytes("x" * 30 + ZWSP))
        scanner = Scanner()
        assert scanner.scan_path(tmp_path) == []
        assert scanner.binary == [str(blob)]

    def test_a_file_that_is_text_from_end_to_end_is_scanned_whatever_its_length(
        self, tmp_path: Path
    ) -> None:
        _looks_binary(tmp_path / "tiny", b"\x01\x01# note " + ZWSP.encode())
        names = [f.char_name for f in Scanner().scan_path(tmp_path)]
        assert names == ["Zero Width Space" + LOOKS_BINARY]

    def test_every_run_in_a_file_is_scanned(self, tmp_path: Path) -> None:
        run = ("x" * 40 + ZWSP + "\n").encode()
        _looks_binary(tmp_path / "blob", HEAD + FILLER + (INVALID + run) * 3)
        assert [(f.line, f.column) for f in Scanner().scan_path(tmp_path)] == [
            (52, 2 + 41),
            (53, 2 + 41),
            (54, 2 + 41),
        ]


class TestDirectives:
    """Never honoured in a file that looks binary, as in dependency code.

    Where the bytes that make a file look binary include a NUL, git shows
    no diff for it, so nobody reviews a directive written into it.
    """

    TEXT = (
        "# heckler-ignore-next-line U+200B\n"
        f"first = 'a{ZWSP}b'\n"
        f"second = 'c{ZWSP}d'  # heckler-ignore U+200B\n"
    )

    def _padded(self) -> bytes:
        return b"# " + b"\x00" * 300 + b"\n" + self.TEXT.encode() + FILLER

    def test_honoured_in_text_and_not_in_a_file_that_looks_binary(self, tmp_path: Path) -> None:
        (tmp_path / "plain").write_bytes(self.TEXT.encode())
        _looks_binary(tmp_path / "padded", self._padded())
        scanner = Scanner()
        findings = scanner.scan_path(tmp_path)
        assert [(Path(f.file).name, f.line) for f in findings] == [("padded", 3), ("padded", 4)]
        assert scanner.suppressed == {str(tmp_path / "plain"): 2}

    def test_allowlist_still_applies(self, tmp_path: Path) -> None:
        _looks_binary(tmp_path / "padded", self._padded())
        assert Scanner(exclude_patterns=["padded"]).scan_path(tmp_path) == []


class TestWhereAFindingIs:
    """Line and column are those of the file as a reviewer sees it."""

    def test_lines_are_counted_over_the_whole_file(self, tmp_path: Path) -> None:
        """LF, CR LF and CR each end a line, in the parts that are not text too."""
        body = (
            b"\x01" * 100
            + b"\n"
            + b"\xff\xff\r\n"
            + b"\xfe\r"
            + b"\xfe\xfd"
            + ("y" * 40 + ZWSP + " tail\n").encode()
            + FILLER
        )
        _looks_binary(tmp_path / "blob", body)
        findings = Scanner().scan_path(tmp_path)
        assert [(f.line, f.column) for f in findings] == [(4, 43)]
        # The column is a position in the line the finding carries, which is
        # what the text report cuts its excerpt from.
        assert findings[0].line_content[findings[0].column - 1] == ZWSP

    def test_padded_text_points_at_the_line_a_reviewer_sees(self, tmp_path: Path) -> None:
        lines = [f"line {number}\n" for number in range(1, 200)]
        lines[1] = "# " + chr(1) * 400 + "\n"
        lines[149] = f"name = 'a{ZWSP}b'\n"
        _looks_binary(tmp_path / "notes", "".join(lines).encode())
        assert [(f.line, f.column) for f in Scanner().scan_path(tmp_path)] == [(150, 10)]


class TestFindingsCap:
    def test_applies_across_the_whole_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Two runs of 6,000 findings each are one file, and it stops at 10,000."""
        run = ("x" * 40 + ZWSP * 6000 + "\n").encode()
        _looks_binary(tmp_path / "blob", b"\x01" * 1024 + INVALID + run + INVALID + run)
        assert len(Scanner().scan_path(tmp_path)) == 10_000
        assert capsys.readouterr().err.count("stopped after 10000 findings") == 1


class TestTooLargeToRead:
    """A file that looks binary and is over the size limit is left out unread.

    It is recorded in ``Scanner.binary`` and named in the note, like a file
    that was read and found to be binary. That is not an error: a
    repository's large media files are not text that went unread.
    """

    @pytest.fixture
    def small_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(scanner_module, "_MAX_SCAN_FILE_SIZE", 64 * 1024)

    def _large_blob(self, path: Path) -> Path:
        return _looks_binary(path, (b"\x00\x01" + f"a{ZWSP}b".encode()) * 12_000)

    def test_recorded_as_binary_and_not_as_skipped(self, tmp_path: Path, small_limit: None) -> None:
        blob = self._large_blob(tmp_path / "video")
        scanner = Scanner()
        assert scanner.scan_path(tmp_path) == []
        assert scanner.binary == [str(blob)]
        assert scanner.skipped == []

    def test_at_the_limit_it_is_read(self, tmp_path: Path, small_limit: None) -> None:
        body = b"\x00\x01" * 300 + f"\nname = 'a{ZWSP}b'\n".encode()
        blob = _looks_binary(tmp_path / "video", body + b"/" * (64 * 1024 - len(body)))
        scanner = Scanner()
        assert len(scanner.scan_path(tmp_path)) == 1
        assert scanner.binary == [str(blob)]
        assert scanner.skipped == []

    def test_cli_names_it_and_does_not_fail(
        self, tmp_path: Path, small_limit: None, capsys: pytest.CaptureFixture[str]
    ) -> None:
        blob = self._large_blob(tmp_path / "video")
        (tmp_path / "ok.txt").write_text("fine\n", encoding="utf-8")
        assert main(["--ci", str(tmp_path)]) == 0
        captured = capsys.readouterr()
        assert f"Note: not scanned as text, binary by content: {blob}." in captured.err
        assert "No dangerous" in captured.out

    def test_passed_by_name_with_skip_binary(self, tmp_path: Path, small_limit: None) -> None:
        blob = self._large_blob(tmp_path / "video")
        scanner = Scanner(skip_binary=True)
        assert scanner.scan_path(blob) == []
        assert scanner.binary == [str(blob)]
        assert scanner.skipped == []

    def test_a_name_that_marks_it_as_source_is_an_error_as_before(
        self, tmp_path: Path, small_limit: None
    ) -> None:
        blob = tmp_path / "video.js"
        blob.write_bytes((b"\x00\x01" + f"a{ZWSP}b".encode()) * 12_000)
        scanner = Scanner()
        assert scanner.scan_path(tmp_path) == []
        assert scanner.binary == []
        assert [path for path, _reason in scanner.skipped] == [str(blob)]


class TestTheNote:
    """The files left out as binary are named, up to five of them."""

    def _blobs(self, root: Path, count: int) -> None:
        for number in range(count):
            _looks_binary(root / f"image{number}", b"\x01\x02\x03\x04" * 64)

    def test_counts_past_five(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        self._blobs(tmp_path, 8)
        assert main(["--ci", str(tmp_path)]) == 0
        note = capsys.readouterr().err
        assert note.count("image") == 5
        assert " and 3 more." in note

    def test_quiet_drops_it(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        self._blobs(tmp_path, 1)
        assert main(["--ci", "--quiet", str(tmp_path)]) == 0
        assert "not scanned" not in capsys.readouterr().err


class TestInsideDependencies:
    def test_all_text_reads_it_and_the_default_keeps_to_code(self, tmp_path: Path) -> None:
        package = tmp_path / "node_modules" / "pkg"
        package.mkdir(parents=True)
        _looks_binary(package / "data.bin", _padded(b"\x00"))
        assert Scanner(scan_deps=True).scan_path(tmp_path) == []
        findings = Scanner(scan_deps=True, all_text=True).scan_path(tmp_path)
        assert [f.char_name for f in findings] == ["Right-to-Left Override" + LOOKS_BINARY]
        assert [(f.source, f.package) for f in findings] == [("dependency", "pkg")]


class TestNamesInNotesAreSpelledOut:
    """A note prints the name of a file, and whoever made the file chose it.

    An escape sequence or a line break in the name of a file left out as
    binary would reach the terminal as it is, where it can wipe the note
    that names the file or add a line that heckler never wrote.
    """

    def test_control_characters_in_the_name_of_a_file_left_out(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        escape, carriage_return = chr(0x1B), chr(0x0D)
        name = f"blob{escape}[2K{carriage_return}ok"
        try:
            (tmp_path / name).write_bytes(bytes(range(256)) * 4)
        except OSError:
            pytest.skip("this filesystem does not take such a name")
        (tmp_path / "a.py").write_text("x = 1\n")
        main(["--no-color", str(tmp_path)])
        err = capsys.readouterr().err
        assert "binary by content" in err
        assert escape not in err
        assert carriage_return not in err
        assert "blob<U+001B>[2K<U+000D>ok" in err
