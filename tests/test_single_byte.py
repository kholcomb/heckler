"""No single byte decides how, or whether, a file is read.

A NUL is the cheapest thing to add to a file, and a block of padding is the
next cheapest. These tests add one or the other to a file that holds a
flagged character and expect the character to be reported all the same.

Everything is built with chr(), so this file holds none of the characters,
and the samples are inert: text in a comment or a string, read by nothing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from heckler.cli import main
from heckler.scanner import Scanner

RLO = chr(0x202E)
ZWSP = chr(0x200B)
SAMPLE = "// settings\n" * 8 + f'const x = "a{RLO}b";\n'
MISMATCH = "Byte order mark for UTF-16 on a file that is not UTF-16"
RLO_AS_UTF8 = "Right-to-Left Override (read as UTF-8)"


def _word(*code_points: int) -> str:
    return "".join(map(chr, code_points))


# A few words in scripts whose UTF-16 bytes look nothing alike.
SCRIPTS = {
    "latin": "plain text",
    "greek": _word(0x3BA, 0x3B5, 0x3AF, 0x3BC, 0x3B5, 0x3BD, 0x3BF),
    "cyrillic": _word(0x434, 0x430, 0x43D, 0x43D, 0x44B, 0x435),
    "hebrew": _word(0x5E9, 0x5DC, 0x5D5, 0x5DD),
    "arabic": _word(0x645, 0x631, 0x62D, 0x628, 0x627),
    "devanagari": _word(0x928, 0x92E, 0x938, 0x94D, 0x924, 0x947),
    "thai": _word(0xE2A, 0xE27, 0xE31, 0xE2A, 0xE14, 0xE35),
    "hiragana": _word(0x3053, 0x308C, 0x306F, 0x3066, 0x3059, 0x3068),
    "japanese": _word(0x65E5, 0x672C, 0x8A9E, 0x306E, 0x30C6, 0x30AD, 0x30B9, 0x30C8),
    "korean": _word(0xD55C, 0xAD6D, 0xC5B4, 0x20, 0xD14D, 0xC2A4, 0xD2B8),
}


def _names(path: Path, **options: object) -> list[str]:
    return [f.char_name for f in Scanner(**options).scan_file(path)]  # type: ignore[arg-type]


class TestNulBehindAByteOrderMark:
    """A NUL after a UTF-16 BOM is not proof that the file is UTF-16."""

    @pytest.mark.parametrize("bom", [b"\xff\xfe", b"\xfe\xff"])
    @pytest.mark.parametrize(
        "body",
        [
            b"\x00" + SAMPLE.encode(),
            b"//\x00\n" + SAMPLE.encode(),
            SAMPLE.encode() + b"\x00",
            SAMPLE.encode().replace(b"settings", b"set\x00ings", 3),
        ],
        ids=["first byte", "in a comment", "last byte", "three of them"],
    )
    def test_utf8_text_with_a_nul_is_still_read_as_utf8(
        self, tmp_path: Path, bom: bytes, body: bytes
    ) -> None:
        f = tmp_path / "page.php"
        f.write_bytes(bom + body)
        names = _names(f)
        assert names[0] == MISMATCH
        assert RLO_AS_UTF8 in names
        assert "Null (read as UTF-8)" in names

    def test_it_fails_ci(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        (tmp_path / "page.php").write_bytes(b"\xff\xfe" + SAMPLE.encode() + b"\x00")
        assert main(["--ci", "--no-color", str(tmp_path)]) == 1
        assert "Right-to-Left Override" in capsys.readouterr().out

    @pytest.mark.parametrize("size", [2, 64, 16384, 200_000])
    def test_utf16_padding_does_not_hide_utf8_text(self, tmp_path: Path, size: int) -> None:
        """Real UTF-16 in front, as much as it takes for the BOM to be believed."""
        f = tmp_path / "page.php"
        padding = ("x" * (size // 2)).encode("utf-16-le")
        f.write_bytes(b"\xff\xfe" + padding + b"\n" + SAMPLE.encode())
        assert RLO_AS_UTF8 in _names(f)

    def test_junk_padding_does_not_hide_utf8_text(self, tmp_path: Path) -> None:
        f = tmp_path / "page.php"
        f.write_bytes(b"\xff\xfe" + bytes(range(0x80, 0x100)) * 8 + b"\n" + SAMPLE.encode())
        assert RLO_AS_UTF8 in _names(f)

    def test_utf32_padding_does_not_hide_utf8_text(self, tmp_path: Path) -> None:
        """Only a file that is UTF-32 to the last byte is believed outright."""
        f = tmp_path / "page.php"
        padding = ("x" * 4096).encode("utf-32-le")
        f.write_bytes(b"\xff\xfe\x00\x00" + padding + b"\n" + SAMPLE.encode())
        names = _names(f)
        assert "Byte order mark for UTF-32 on a file that is not UTF-32" in names
        assert RLO_AS_UTF8 in names

    def test_utf8_inside_units_that_are_valid_utf32(self, tmp_path: Path) -> None:
        """Two bytes of UTF-8 and two NULs make a valid UTF-32 unit."""
        f = tmp_path / "page.php"
        soft_hyphen = chr(0xAD).encode()  # two bytes
        f.write_bytes(b"\xff\xfe\x00\x00" + (b"ab\x00\x00" * 4 + soft_hyphen + b"\x00\x00") * 4)
        assert "Soft Hyphen (read as UTF-8)" in _names(f)


class TestRealUtf16IsStillBelieved:
    """The other side of the rule: text that is UTF-16 is read once, without noise."""

    @pytest.mark.parametrize("script", sorted(SCRIPTS))
    @pytest.mark.parametrize(
        ("bom", "codec"), [(b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be")]
    )
    def test_text_with_a_finding(self, tmp_path: Path, script: str, bom: bytes, codec: str) -> None:
        word = SCRIPTS[script]
        text = f"{word} {word}\n" * 6 + f'x = "{RLO}";\n'
        f = tmp_path / "notes.txt"
        f.write_bytes(bom + text.encode(codec))
        assert _names(f) == ["Right-to-Left Override"]

    @pytest.mark.parametrize("script", sorted(SCRIPTS))
    @pytest.mark.parametrize(
        ("bom", "codec"), [(b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be")]
    )
    def test_clean_text(self, tmp_path: Path, script: str, bom: bytes, codec: str) -> None:
        word = SCRIPTS[script]
        f = tmp_path / "notes.txt"
        f.write_bytes(bom + (f"{word} {word}\n" * 6).encode(codec))
        assert _names(f) == []

    def test_unbroken_cjk_without_a_line_break(self, tmp_path: Path) -> None:
        f = tmp_path / "notes.txt"
        f.write_bytes(b"\xff\xfe" + (SCRIPTS["japanese"] * 40).encode("utf-16-le"))
        assert _names(f) == []


class TestEncodingsWithoutAByteOrderMark:
    """The character is named, not only the NUL or control bytes around it."""

    @pytest.mark.parametrize("script", ["greek", "cyrillic", "hebrew", "arabic", "thai"])
    @pytest.mark.parametrize(("codec", "label"), [("utf-16-le", "LE"), ("utf-16-be", "BE")])
    def test_utf16_with_no_ascii_in_it(
        self, tmp_path: Path, script: str, codec: str, label: str
    ) -> None:
        word = SCRIPTS[script]
        text = f"{word}{word}\n" * 6 + f"{word}{RLO}{word}\n"
        f = tmp_path / "notes.txt"
        f.write_bytes(text.encode(codec))
        assert f"Right-to-Left Override (read as UTF-16 {label})" in _names(f)

    @pytest.mark.parametrize(("codec", "label"), [("utf-32-le", "LE"), ("utf-32-be", "BE")])
    def test_utf32(self, tmp_path: Path, codec: str, label: str) -> None:
        f = tmp_path / "evil.js"
        f.write_bytes(SAMPLE.encode(codec))
        assert f"Right-to-Left Override (read as UTF-32 {label})" in _names(f)

    @pytest.mark.parametrize(
        "content",
        [
            b"x\n" * 200,
            b"\tab\r\n" * 200,
            b"\x00" * 64 + b"const p = 1;\n" * 4,
            b"\x1b[32mok\x1b[0m step\n" * 50,
            bytes(range(256)) * 8,
        ],
        ids=["short lines", "tabs and CRLF", "NUL block", "escape codes", "every byte"],
    )
    def test_other_content_is_read_once(self, tmp_path: Path, content: bytes) -> None:
        f = tmp_path / "data.js"
        f.write_bytes(content)
        assert not [name for name in _names(f) if "read as" in name]


class TestNulInAFileWithANameThatSaysNothing:
    """Content decides whether such a file is left out. One byte does not."""

    def _scan(self, root: Path) -> tuple[list[str], list[str]]:
        scanner = Scanner()
        names = [f.char_name for f in scanner.scan_path(root)]
        return names, [Path(p).name for p in scanner.binary]

    @pytest.mark.parametrize(
        "content",
        [
            b"// first comment \x00\n",
            b"\x00// first comment\n",
            b"// first comment " + b"\x00" * 16 + b"\n",
        ],
        ids=["in the comment", "first byte", "sixteen of them"],
    )
    def test_script_with_a_nul_is_scanned(self, tmp_path: Path, content: bytes) -> None:
        body = content + f"const x = 'a{ZWSP}b';\n".encode() + b"const y = 2;\n" * 40
        (tmp_path / "cli").write_bytes(body)
        names, binary = self._scan(tmp_path)
        assert "Zero Width Space" in names
        assert "Null" in names
        assert binary == []

    def test_shebang_script_is_scanned_whatever_else_it_holds(self, tmp_path: Path) -> None:
        """The kernel runs it as a script, so it is one."""
        body = b"#!/usr/bin/env node\n" + bytes(range(0x20)) * 64
        (tmp_path / "cli").write_bytes(body + f"\nconst x = 'a{ZWSP}b';\n".encode())
        names, binary = self._scan(tmp_path)
        assert "Zero Width Space" in names
        assert binary == []

    def test_coloured_log_is_text(self, tmp_path: Path) -> None:
        line = b"\x1b[32mok\x1b[0m step\n"
        (tmp_path / "build.out").write_bytes(line * 200)
        names, binary = self._scan(tmp_path)
        assert set(names) == {"Escape"}
        assert binary == []

    @pytest.mark.parametrize("control", [b"\x00", b"\x01"], ids=["NUL", "U+0001"])
    @pytest.mark.parametrize("size", [1, 2, 16, 31])
    def test_one_control_byte_in_a_tiny_file(
        self, tmp_path: Path, control: bytes, size: int
    ) -> None:
        """A 31-byte file with one NUL was left out: one byte in 31 is more than one in 32."""
        (tmp_path / "cli").write_bytes(control + b"# a comment that says nothing\n"[: size - 1])
        assert (tmp_path / "cli").stat().st_size == size
        names, binary = self._scan(tmp_path)
        assert names == ["Null" if control == b"\x00" else "Control Character U+0001"]
        assert binary == []

    def test_tiny_file_with_a_nul_is_scanned_as_text(self, tmp_path: Path) -> None:
        body = b"\x00" + f"# 'a{ZWSP}b' ".encode().ljust(30, b"#")
        assert len(body) == 31
        (tmp_path / "cli").write_bytes(body)
        names, _binary = self._scan(tmp_path)
        assert names == ["Null", "Zero Width Space"]

    @pytest.mark.parametrize(
        "content",
        [
            b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 16,
            b"\x7fELF" + b"\x00" * 600 + b"text " * 100,
            b"PK\x03\x04" + bytes(range(256)) * 4,
        ],
        ids=["png", "elf", "zip"],
    )
    def test_binary_is_left_out_and_recorded(self, tmp_path: Path, content: bytes) -> None:
        # Bytes that are U+00A0 when read as text.
        (tmp_path / "blob").write_bytes(content + chr(0xA0).encode() * 10)
        names, binary = self._scan(tmp_path)
        assert names == []
        assert binary == ["blob"]

    def test_mostly_text_behind_a_binary_header_is_scanned(self, tmp_path: Path) -> None:
        """A header and 60 NUL bytes in front of 500 bytes of text.

        The start looks binary, and that used to leave the text out. Over
        the whole file the NUL bytes are a tenth, so it is mostly text.
        """
        content = b"\x7fELF" + b"\x00" * 60 + b"text " * 100
        (tmp_path / "blob").write_bytes(content + chr(0xA0).encode() * 10)
        names, binary = self._scan(tmp_path)
        assert names == ["No-Break Space (in a file that looks binary)"] * 10
        assert binary == []

    def test_recognised_name_is_not_recorded_as_binary(self, tmp_path: Path) -> None:
        (tmp_path / "blob.js").write_bytes(b"\x00" * 200)
        names, binary = self._scan(tmp_path)
        assert names == ["Null"]
        assert binary == []

    def test_cli_names_the_files_it_left_out(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "blob").write_bytes(b"\x00" * 200)
        (tmp_path / "ok.txt").write_text("fine\n", encoding="utf-8")
        assert main(["--ci", str(tmp_path)]) == 0
        note = f"Note: not scanned, binary by content: {tmp_path / 'blob'}."
        assert note in capsys.readouterr().err

    def test_cli_says_nothing_when_nothing_was_left_out(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "ok.txt").write_text("fine\n", encoding="utf-8")
        assert main(["--ci", str(tmp_path)]) == 0
        assert "binary" not in capsys.readouterr().err
