"""Tests for threat-model hardening fixes.

Covers: U+2028/2029 detection, heckler-ignore comment enforcement,
null-byte injection resistance, missing --config error, unsupported
ecosystem warnings, and zip member filtering.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from heckler.characters import DANGEROUS_UNICODE_RE, Severity, get_char_info
from heckler.cli import main
from heckler.config import load_config
from heckler.lockfile import parse_changed_packages
from heckler.scanner import (
    DEFAULT_TEXT_EXTENSIONS,
    DEP_SCAN_EXTENSIONS,
    KNOWN_FILENAMES,
    Scanner,
)
from heckler.vet import _safe_zip_extract, extract_package

# ---------------------------------------------------------------------------
# 1. U+2028 / U+2029 detection
# ---------------------------------------------------------------------------


class TestLineParagraphSeparators:
    def test_regex_matches_u2028(self) -> None:
        assert DANGEROUS_UNICODE_RE.search("\u2028")

    def test_regex_matches_u2029(self) -> None:
        assert DANGEROUS_UNICODE_RE.search("\u2029")

    def test_char_info_u2028(self) -> None:
        info = get_char_info(0x2028)
        assert info.name == "Line Separator"
        assert info.severity == Severity.HIGH

    def test_char_info_u2029(self) -> None:
        info = get_char_info(0x2029)
        assert info.name == "Paragraph Separator"
        assert info.severity == Severity.HIGH

    def test_scanner_finds_line_separator(self) -> None:
        scanner = Scanner()
        text = 'const x = "a\u2028b";\n'
        findings = scanner.scan_text(text)
        assert len(findings) == 1
        assert findings[0].codepoint == 0x2028

    def test_scanner_finds_paragraph_separator(self) -> None:
        scanner = Scanner()
        text = 'const x = "a\u2029b";\n'
        findings = scanner.scan_text(text)
        assert len(findings) == 1
        assert findings[0].codepoint == 0x2029


# ---------------------------------------------------------------------------
# 2. Suppression directive hardening
# ---------------------------------------------------------------------------


class TestNextLineDirective:
    """Tests for the heckler-ignore-next-line directive."""

    def test_next_line_suppresses_medium_and_below(self) -> None:
        scanner = Scanner()
        text = '// heckler-ignore-next-line\nconst x = "\u200b\u00ad\u2062";\n'
        assert scanner.scan_text(text) == []

    def test_next_line_python_comment(self) -> None:
        scanner = Scanner()
        text = '# heckler-ignore-next-line\nx = "\u200b"\n'
        assert scanner.scan_text(text) == []

    def test_next_line_sql_comment(self) -> None:
        scanner = Scanner()
        text = '-- heckler-ignore-next-line\nSELECT "\u200b";\n'
        assert scanner.scan_text(text) == []

    def test_next_line_block_comment(self) -> None:
        scanner = Scanner()
        text = '/* heckler-ignore-next-line */\nconst x = "\u200b";\n'
        assert scanner.scan_text(text) == []

    def test_next_line_semicolon_comment(self) -> None:
        scanner = Scanner()
        text = '; heckler-ignore-next-line\nkey = "\u200b"\n'
        assert scanner.scan_text(text) == []

    @pytest.mark.parametrize("opener", [";;", "##", "///", "/**"])
    def test_next_line_repeated_comment_character(self, opener: str) -> None:
        text = f'{opener} heckler-ignore-next-line\nkey = "\u200b"\n'
        assert Scanner().scan_text(text) == []

    def test_next_line_only_affects_one_line(self) -> None:
        scanner = Scanner()
        text = '// heckler-ignore-next-line\nconst x = "\u200b";\nconst y = "\u200c";\n'
        findings = scanner.scan_text(text)
        assert len(findings) == 1
        assert findings[0].codepoint == 0x200C

    def test_next_line_directive_on_a_clean_line(self) -> None:
        scanner = Scanner()
        text = "// heckler-ignore-next-line\nclean line\n"
        assert scanner.scan_text(text) == []

    def test_directive_line_is_scanned_too(self) -> None:
        """A directive covers the line after it, not itself."""
        text = "/* heckler-ignore-next-line */\n// heckler-ignore-next-line\nx = 1\n"
        assert Scanner().scan_text(text) == []
        # The same two lines with a zero width space smuggled into the second:
        # it no longer reads as a directive, and it is reported.
        text = "x = 1\n// heckler-ignore-next-line\u200b\ny = '\u200c'\n"
        assert [(f.line, f.codepoint) for f in Scanner().scan_text(text)] == [
            (2, 0x200B),
            (3, 0x200C),
        ]

    def test_previous_directive_covers_a_directive_line(self) -> None:
        text = "# heckler-ignore-next-line U+200B\n# heckler-ignore-next-line\u200b\nx = '\u200c'\n"
        # Line 2 is not a directive (it does not end after the keyword), so
        # line 3 is reported; line 2's own character is covered by line 1.
        assert [(f.line, f.codepoint) for f in Scanner().scan_text(text)] == [(3, 0x200C)]


class TestBareDirective:
    """Without a codepoint list, a directive covers MEDIUM and below."""

    @pytest.mark.parametrize(
        ("cp", "severity"),
        [
            (0x202E, Severity.CRITICAL),  # Right-to-Left Override
            (0xFE01, Severity.CRITICAL),  # Variation Selector 2
            (0x2066, Severity.HIGH),  # Left-to-Right Isolate
            (0xE0041, Severity.HIGH),  # Tag 'A'
            (0x001B, Severity.HIGH),  # Escape
        ],
    )
    def test_high_and_critical_are_still_reported(self, cp: int, severity: Severity) -> None:
        for text in (
            f"// heckler-ignore-next-line\nconst x = '{chr(cp)}';\n",
            f"const x = '{chr(cp)}'; // heckler-ignore\n",
        ):
            findings = Scanner().scan_text(text)
            assert [(f.codepoint, f.severity) for f in findings] == [(cp, severity)]

    @pytest.mark.parametrize("cp", [0x200B, 0x200D, 0x2062, 0x3164, 0x00AD, 0x00A0, 0x0008])
    def test_medium_and_low_are_suppressed(self, cp: int) -> None:
        for text in (
            f"// heckler-ignore-next-line\nconst x = '{chr(cp)}';\n",
            f"const x = '{chr(cp)}'; // heckler-ignore\n",
        ):
            assert Scanner().scan_text(text) == []

    def test_mixed_line_keeps_only_what_needs_listing(self) -> None:
        text = "x = 'a\u200bb\u202ec'  # heckler-ignore\n"
        assert [f.codepoint for f in Scanner().scan_text(text)] == [0x202E]

    def test_listing_the_codepoint_suppresses_it(self) -> None:
        text = "x = 'a\u200bb\u202ec'  # heckler-ignore U+202E\n"
        # A list is exact: the zero width space is not on it.
        assert [f.codepoint for f in Scanner().scan_text(text)] == [0x200B]

    def test_inline_and_next_line_directives_add_up(self) -> None:
        text = "# heckler-ignore-next-line U+202E\nx = 'a\u200bb\u202ec'  # heckler-ignore\n"
        assert Scanner().scan_text(text) == []

    def test_scanner_counts_what_was_suppressed_and_what_was_not(self) -> None:
        scanner = Scanner()
        scanner.scan_text("x = 'a\u200bb\u00adc\u202ed'  # heckler-ignore\n", "a.py")
        scanner.scan_text("y = '\u202e'  # heckler-ignore U+202E\n", "b.py")
        scanner.scan_text("z = '\u202e'\n", "c.py")
        assert scanner.suppressed == {"a.py": 2, "b.py": 1}
        assert scanner.unlisted == 1

    def test_findings_below_the_threshold_are_not_counted_as_suppressed(self) -> None:
        scanner = Scanner(severity_threshold=Severity.HIGH)
        scanner.scan_text("x = 'a\u200bb'  # heckler-ignore\n", "a.py")
        assert scanner.suppressed == {}


class TestCodepointSpecificSuppression:
    """Tests for codepoint-specific suppression (U+XXXX)."""

    def test_next_line_specific_codepoint_suppressed(self) -> None:
        scanner = Scanner()
        text = '// heckler-ignore-next-line U+FE0F\nconst emoji = "\ufe0f";\n'
        assert scanner.scan_text(text) == []

    def test_next_line_specific_codepoint_others_still_found(self) -> None:
        scanner = Scanner()
        text = '// heckler-ignore-next-line U+FE0F\nconst x = "\ufe0f\u202e";\n'
        findings = scanner.scan_text(text)
        assert len(findings) == 1
        assert findings[0].codepoint == 0x202E

    def test_next_line_multiple_codepoints(self) -> None:
        scanner = Scanner()
        text = '// heckler-ignore-next-line U+FE0F U+FE0E\nconst x = "\ufe0f\ufe0e";\n'
        assert scanner.scan_text(text) == []

    def test_inline_specific_codepoint(self) -> None:
        scanner = Scanner()
        text = 'const x = "\ufe0f"; // heckler-ignore U+FE0F\n'
        assert scanner.scan_text(text) == []

    def test_inline_specific_codepoint_others_found(self) -> None:
        scanner = Scanner()
        text = 'const x = "\ufe0f\u202e"; // heckler-ignore U+FE0F\n'
        findings = scanner.scan_text(text)
        assert len(findings) == 1
        assert findings[0].codepoint == 0x202E


class TestLegacyInlineSuppression:
    """Legacy inline heckler-ignore still works for project code."""

    def test_js_comment_still_works(self) -> None:
        scanner = Scanner()
        text = 'const x = "\u200b"; // heckler-ignore\n'
        assert scanner.scan_text(text) == []

    def test_python_comment_still_works(self) -> None:
        scanner = Scanner()
        text = 'x = "\u200b"  # heckler-ignore\n'
        assert scanner.scan_text(text) == []

    def test_sql_comment_still_works(self) -> None:
        scanner = Scanner()
        text = 'SELECT "\u200b"; -- heckler-ignore\n'
        assert scanner.scan_text(text) == []

    def test_block_comment_still_works(self) -> None:
        scanner = Scanner()
        text = 'const x = "\u200b"; /* heckler-ignore */\n'
        assert scanner.scan_text(text) == []

    def test_semicolon_comment_still_works(self) -> None:
        scanner = Scanner()
        text = 'key = "\u200b" ; heckler-ignore\n'
        assert scanner.scan_text(text) == []

    @pytest.mark.parametrize("opener", [";;", "##", "///", "/**"])
    def test_repeated_comment_character_still_works(self, opener: str) -> None:
        close = " */" if opener == "/**" else ""
        text = f'key = "\u200b" {opener} heckler-ignore{close}\n'
        assert Scanner().scan_text(text) == []


class TestSuppressionBypassPrevention:
    """Verify that known bypass vectors are blocked."""

    def test_url_fragment_does_not_suppress(self) -> None:
        """#heckler-ignore inside a URL must NOT suppress detection."""
        scanner = Scanner()
        text = 'const url = "https://evil.com#heckler-ignore"; const x = "\u202e";\n'
        findings = scanner.scan_text(text)
        assert any(f.codepoint == 0x202E for f in findings)

    def test_url_double_slash_does_not_suppress(self) -> None:
        """//heckler-ignore inside a URL must NOT suppress detection."""
        scanner = Scanner()
        text = 'const url = "http://proxy//heckler-ignore\u202e";\n'
        findings = scanner.scan_text(text)
        assert any(f.codepoint == 0x202E for f in findings)

    def test_string_literal_does_not_suppress(self) -> None:
        scanner = Scanner()
        text = 'x = "heckler-ignore"; auth = "\u202e"\n'
        findings = scanner.scan_text(text)
        assert any(f.codepoint == 0x202E for f in findings)

    def test_mid_line_directive_with_trailing_code(self) -> None:
        """Inline directive with code after it should NOT suppress."""
        scanner = Scanner()
        text = 'x = 1; // heckler-ignore\n; y = "\u202e";\n'
        # The directive is end-of-line anchored, so line 1 is suppressed
        # but line 2 (with the dangerous char) is not
        findings = scanner.scan_text(text)
        assert any(f.codepoint == 0x202E for f in findings)

    def test_variable_name_does_not_suppress(self) -> None:
        scanner = Scanner()
        text = 'heckler_ignore = "\ufe01"\n'
        findings = scanner.scan_text(text)
        assert len(findings) == 1

    def test_partial_match_does_not_suppress(self) -> None:
        scanner = Scanner()
        text = 'msg = "run heckler-ignore check \ufe01"\n'
        findings = scanner.scan_text(text)
        assert len(findings) == 1

    # Each of these ends a line with text shaped like a directive that no
    # language reads as a comment. The planted character is a zero width
    # space, which a real bare directive would cover.
    @pytest.mark.parametrize(
        "line",
        [
            pytest.param("see https://example.test/a\u200bb#heckler-ignore", id="url-fragment"),
            pytest.param("fetch a\u200bb from https://heckler-ignore", id="url-authority"),
            pytest.param("run: tool a\u200bb --heckler-ignore", id="command-line-flag"),
            pytest.param("x = 'a\u200bb';heckler-ignore", id="statement-after-semicolon"),
            pytest.param("x = 'a\u200bb' --heckler-ignore", id="double-dash-without-space"),
            pytest.param("glob: src/a\u200bb/*heckler-ignore", id="glob-star"),
            pytest.param("x = 'a\u200bb' #\u00a0heckler-ignore", id="no-break-space-after-hash"),
            pytest.param("x = 'a\u200bb' //\u2003heckler-ignore", id="em-space-after-slashes"),
            pytest.param("x = 'a\u200bb' // heckler-ignore\u2000U+200B", id="en-quad-before-list"),
        ],
    )
    def test_directive_shaped_text_is_not_a_directive(self, line: str) -> None:
        scanner = Scanner()
        findings = scanner.scan_text(line + "\n")
        assert 0x200B in [f.codepoint for f in findings]
        assert scanner.suppressed == {}

    @pytest.mark.parametrize(
        "line",
        [
            "--heckler-ignore-next-line",
            "#\u00a0heckler-ignore-next-line",
            "//\u3000heckler-ignore-next-line",
            "x = 1  // heckler-ignore-next-line",
        ],
    )
    def test_next_line_shaped_text_is_not_a_directive(self, line: str) -> None:
        findings = Scanner().scan_text(f"{line}\ny = 'a\u200bb'\n")
        assert (2, 0x200B) in [(f.line, f.codepoint) for f in findings]

    def test_exotic_space_inside_a_directive_is_reported(self) -> None:
        """Only spaces and tabs may separate the parts of a directive."""
        findings = Scanner().scan_text("# heckler-ignore-next-line\u00a0U+202E\nx = '\u202e'\n")
        assert [(f.line, f.codepoint) for f in findings] == [(1, 0x00A0), (2, 0x202E)]


class TestCarriageReturnLineEndings:
    """CR on its own ends a line, as it does in an editor."""

    def test_line_numbers_match_an_editor(self) -> None:
        findings = Scanner().scan_text("a = 1\rb = '\u202e'\rc = 3\r")
        assert [(f.line, f.column) for f in findings] == [(2, 6)]

    def test_inline_directive_covers_its_own_line_only(self) -> None:
        """Read as one long line, the directive at the end would cover all of it."""
        text = "a = '\u200b'\rb = '\u200c'\rc = '\u200d' # heckler-ignore\r"
        assert [(f.line, f.codepoint) for f in Scanner().scan_text(text)] == [
            (1, 0x200B),
            (2, 0x200C),
        ]

    def test_next_line_directive_works(self) -> None:
        text = "# heckler-ignore-next-line\ra = '\u200b'\rb = '\u200c'\r"
        assert [(f.line, f.codepoint) for f in Scanner().scan_text(text)] == [(3, 0x200C)]

    def test_mixed_line_endings(self) -> None:
        findings = Scanner().scan_text("a\r\nb\rc\nd '\u200b'\n")
        assert [f.line for f in findings] == [4]

    def test_line_content_has_no_line_ending(self) -> None:
        findings = Scanner().scan_text("x = '\u200b'\r\ny = 2\r\n")
        assert findings[0].line_content == "x = '\u200b'"

    def test_unicode_line_separators_are_still_reported_not_split_on(self) -> None:
        findings = Scanner().scan_text("a\u2028b\u2029c\x85d\n")
        assert [(f.line, f.codepoint) for f in findings] == [(1, 0x2028), (1, 0x2029), (1, 0x85)]


class TestNoSuppress:
    def test_scanner_can_ignore_directives(self) -> None:
        text = "x = 'a\u200bb'  # heckler-ignore\n# heckler-ignore-next-line U+202E\ny = '\u202e'\n"
        assert Scanner().scan_text(text) == []
        scanner = Scanner(honor_directives=False)
        assert [f.codepoint for f in scanner.scan_text(text)] == [0x200B, 0x202E]
        assert scanner.suppressed == {}

    def test_cli_reports_how_much_was_suppressed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "a.py").write_text(
            "x = 'a\u200bb\u00adc'  # heckler-ignore\n", encoding="utf-8"
        )
        (tmp_path / "b.py").write_text("y = '\u202e'  # heckler-ignore U+202E\n", encoding="utf-8")
        (tmp_path / "c.py").write_text("z = 1\n", encoding="utf-8")

        assert main(["--ci", str(tmp_path)]) == 0
        captured = capsys.readouterr()
        assert "3 finding(s) suppressed in 2 file(s)" in captured.err
        assert "--no-suppress" in captured.err
        assert "No dangerous" in captured.out

    def test_cli_no_suppress_lists_them(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "a.py").write_text("x = 'a\u200bb'  # heckler-ignore\n", encoding="utf-8")
        assert main(["--ci", "--no-suppress", str(tmp_path)]) == 1
        captured = capsys.readouterr()
        assert "U+200B" in captured.out
        assert "suppressed" not in captured.err

    def test_cli_says_nothing_when_nothing_was_suppressed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "a.py").write_text("x = 1  # heckler-ignore\n", encoding="utf-8")
        assert main(["--ci", str(tmp_path)]) == 0
        assert capsys.readouterr().err == ""

    def test_cli_explains_a_directive_that_does_not_cover_its_line(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "a.py").write_text("x = '\u202e'  # heckler-ignore\n", encoding="utf-8")
        assert main(["--ci", str(tmp_path)]) == 1
        captured = capsys.readouterr()
        assert "U+202E" in captured.out
        assert "does not cover them" in captured.err
        assert "heckler-ignore U+FE0F" in captured.err

    def test_json_output_stays_clean(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "a.py").write_text("x = 'a\u200bb'  # heckler-ignore\n", encoding="utf-8")
        assert main(["--format", "json", str(tmp_path)]) == 0
        captured = capsys.readouterr()
        assert json.loads(captured.out) == []
        assert "1 finding(s) suppressed in 1 file(s)" in captured.err

    def test_quiet_leaves_the_note_out(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "a.py").write_text("x = 'a\u200bb'  # heckler-ignore\n", encoding="utf-8")
        assert main(["--quiet", str(tmp_path)]) == 0
        assert capsys.readouterr().err == ""


class TestDependencySuppressionBlocked:
    """Suppression directives must NEVER be honored in dependency code."""

    def test_dependency_inline_ignore_not_honored(self) -> None:
        scanner = Scanner()
        text = 'const x = "\ufe01"; // heckler-ignore\n'
        findings = scanner.scan_text(text, "node_modules/evil/index.js")
        assert len(findings) == 1
        assert findings[0].codepoint == 0xFE01

    def test_dependency_next_line_not_honored(self) -> None:
        scanner = Scanner()
        text = '// heckler-ignore-next-line\nconst x = "\u202e";\n'
        findings = scanner.scan_text(text, "node_modules/evil/index.js")
        assert len(findings) == 1
        assert findings[0].codepoint == 0x202E

    def test_dependency_codepoint_specific_not_honored(self) -> None:
        scanner = Scanner()
        text = '// heckler-ignore-next-line U+FE0F\nconst x = "\ufe0f";\n'
        findings = scanner.scan_text(text, "node_modules/evil/index.js")
        assert len(findings) == 1

    def test_dependency_site_packages_not_honored(self) -> None:
        scanner = Scanner()
        text = '# heckler-ignore-next-line\nx = "\ufe01"\n'
        findings = scanner.scan_text(text, "site-packages/evil/__init__.py")
        assert len(findings) == 1

    def test_project_code_still_honored(self) -> None:
        """Sanity check: same directive works for project code."""
        scanner = Scanner()
        text = '// heckler-ignore-next-line U+202E\nconst x = "\u202e";\n'
        findings = scanner.scan_text(text, "src/app.js")
        assert findings == []

    def test_dependency_bare_directive_not_honored_for_medium(self) -> None:
        text = '// heckler-ignore-next-line\nconst x = "\u200b"; // heckler-ignore\n'
        scanner = Scanner()
        assert len(scanner.scan_text(text, "node_modules/evil/index.js")) == 1
        assert scanner.suppressed == {}


# ---------------------------------------------------------------------------
# 3. Null-byte injection resistance
# ---------------------------------------------------------------------------


class TestNullByteHardening:
    def test_null_after_dangerous_chars_still_detected(self, tmp_path: Path) -> None:
        """Dangerous chars before a null byte should still be found."""
        f = tmp_path / "tricky.js"
        content = 'const x = "\ufe01";\n'.encode() + b"\x00binary stuff"
        f.write_bytes(content)

        scanner = Scanner()
        findings = scanner.scan_file(f)
        assert [x.codepoint for x in findings] == [0xFE01, 0x00]

    def test_control_bytes_in_a_source_file_are_reported(self, tmp_path: Path) -> None:
        f = tmp_path / "binary.js"
        f.write_bytes(b"\x00\x01\x02")
        assert [x.codepoint for x in Scanner().scan_file(f)] == [0x00, 0x01, 0x02]

    def test_null_before_dangerous_chars_does_not_hide_them(self, tmp_path: Path) -> None:
        """A NUL in a comment on line 1 must not stop the scan."""
        f = tmp_path / "hidden.js"
        f.write_bytes(b"//\x00\n" + "const p = `\ufe01\ufe02\ufe03`;\n".encode())

        findings = Scanner().scan_file(f)
        assert [(x.line, x.codepoint) for x in findings] == [
            (1, 0x00),
            (2, 0xFE01),
            (2, 0xFE02),
            (2, 0xFE03),
        ]

    def test_leading_null_does_not_hide_the_file(self, tmp_path: Path) -> None:
        """PHP emits anything before its opening tag, so a file can start with NUL."""
        f = tmp_path / "page.php"
        f.write_bytes(b"\x00\x00<?php\n" + '$p = "\u202e";\n'.encode())

        findings = Scanner().scan_file(f)
        # Two NUL bytes, one finding: NUL is reported once per file.
        assert [x.codepoint for x in findings] == [0x00, 0x202E]

    def test_null_does_not_hide_chars_in_directory_walk(self, tmp_path: Path) -> None:
        (tmp_path / "hidden.js").write_bytes(
            b"//\x00\n" + "const p = `\ufe01`;\n".encode(),
        )
        assert len(Scanner().scan_path(tmp_path)) == 2
        assert len(Scanner(text_extensions=None).scan_path(tmp_path)) == 2

    def test_null_byte_midfile_scans_prefix(self, tmp_path: Path) -> None:
        """Dangerous chars in the text portion before null should be found."""
        f = tmp_path / "mixed.js"
        evil = "line1 \u200b ok\nline2 \u202e bad\n".encode()
        f.write_bytes(evil + b"\x00" + b"binary tail")
        scanner = Scanner()
        findings = scanner.scan_file(f)
        assert [x.codepoint for x in findings] == [0x200B, 0x202E, 0x00]


class TestAllTextBinaryFilter:
    """With no extension filter, content decides what is left out."""

    def test_unrecognised_binary_is_skipped(self, tmp_path: Path) -> None:
        # Bytes that would decode to U+00A0 if the file were read as text.
        (tmp_path / "blob.bin").write_bytes(b"\x89PNG\x00\x00" + b"\xc2\xa0" * 10)
        assert Scanner(text_extensions=None).scan_path(tmp_path) == []

    def test_unrecognised_text_is_scanned(self, tmp_path: Path) -> None:
        (tmp_path / "notes.weird").write_text("a\u200bb\n", encoding="utf-8")
        assert len(Scanner(text_extensions=None).scan_path(tmp_path)) == 1

    def test_unrecognised_utf16_is_scanned(self, tmp_path: Path) -> None:
        (tmp_path / "notes.weird").write_bytes(
            b"\xff\xfe" + 'x = "\u202e";\n'.encode("utf-16-le"),
        )
        assert len(Scanner(text_extensions=None).scan_path(tmp_path)) == 1

    def test_known_filename_with_null_is_scanned(self, tmp_path: Path) -> None:
        (tmp_path / "Makefile").write_bytes(b"#\x00\n" + "x = \u202e\n".encode())
        assert len(Scanner(text_extensions=None).scan_path(tmp_path)) == 2


# ---------------------------------------------------------------------------
# 4. Missing --config path error
# ---------------------------------------------------------------------------


class TestMissingConfigError:
    def test_load_config_raises_on_missing_explicit_path(self) -> None:
        with pytest.raises(FileNotFoundError, match="Config file not found"):
            load_config(config_path="/nonexistent/policy.yml")

    def test_cli_returns_2_on_missing_config(self, tmp_path: Path) -> None:
        (tmp_path / "clean.js").write_text("x = 1\n", encoding="utf-8")
        result = main(["--config", "/nonexistent/policy.yml", str(tmp_path)])
        assert result == 2

    def test_auto_discover_missing_is_fine(self) -> None:
        """Without --config, missing files should NOT raise."""
        config = load_config()
        assert config.severity_threshold == Severity.LOW


# ---------------------------------------------------------------------------
# 5. Unsupported ecosystem warnings
# ---------------------------------------------------------------------------


class TestUnsupportedEcosystemWarning:
    def test_cargo_emits_warning(self, capsys: object) -> None:
        parse_changed_packages("+some-crate = 1.0\n", "cargo")
        captured = capsys.readouterr()  # type: ignore[attr-defined]
        assert "not yet supported" in captured.err

    def test_go_emits_warning(self, capsys: object) -> None:
        parse_changed_packages("+golang.org/x/text v0.3.0\n", "go")
        captured = capsys.readouterr()  # type: ignore[attr-defined]
        assert "not yet supported" in captured.err

    def test_npm_does_not_warn(self, capsys: object) -> None:
        parse_changed_packages("", "npm")
        captured = capsys.readouterr()  # type: ignore[attr-defined]
        assert "not yet supported" not in captured.err


# ---------------------------------------------------------------------------
# 6. Zip member filtering
# ---------------------------------------------------------------------------


class TestZipMemberFiltering:
    def test_zip_extracts_validated_members_individually(self, tmp_path: Path) -> None:
        """Ensure zip extraction still works correctly after switching
        from extractall() to individual extract()."""
        zip_path = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("pkg/index.js", b"module.exports = {};")
            zf.writestr("pkg/lib/util.js", b"exports.x = 1;")

        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        _safe_zip_extract(zip_path, extract_dir, extract_dir.resolve())

        assert (extract_dir / "pkg" / "index.js").exists()
        assert (extract_dir / "pkg" / "lib" / "util.js").exists()

    def test_wheel_with_planted_chars_detected(self, tmp_path: Path) -> None:
        """End-to-end: a .whl with dangerous chars is extracted and scanned."""
        evil_py = 'access = "\u202eadmin"\n'.encode()
        whl_path = tmp_path / "evil-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(whl_path, "w") as zf:
            zf.writestr("evil/__init__.py", evil_py)

        extract_dir = extract_package(whl_path, str(tmp_path))
        scanner = Scanner(skip_dirs=frozenset(), scan_deps=True)
        findings = scanner.scan_path(extract_dir)
        assert len(findings) == 1
        assert findings[0].codepoint_hex == "U+202E"


# ---------------------------------------------------------------------------
# 7. Extended file extensions
# ---------------------------------------------------------------------------


class TestExtendedExtensions:
    # Expected extensions added across the hardening commits.
    _EXPECTED = {
        ".ps1",
        ".bat",
        ".cmd",
        ".fish",
        ".ejs",
        ".hbs",
        ".gradle",
        ".proto",
        ".graphql",
        ".dart",
        ".ex",
        ".exs",
        ".erl",
        ".hrl",
        ".zig",
        ".nim",
        ".ml",
        ".mli",
        ".hs",
        ".lhs",
        ".clj",
        ".cljs",
        ".cljc",
        ".jl",
        ".elm",
        ".v",
        ".d",
        ".ada",
        ".adb",
        ".ads",
        ".f90",
        ".groovy",
        ".cr",
        ".purs",
        ".rkt",
        ".lisp",
        ".cl",
        ".el",
        ".asm",
        ".s",
        ".m",
        ".mm",
        ".vb",
        ".vbs",
        ".pp",
        ".pas",
        ".tcl",
    }

    def test_all_expected_extensions_present(self) -> None:
        missing = self._EXPECTED - DEFAULT_TEXT_EXTENSIONS
        assert not missing, f"Missing from DEFAULT_TEXT_EXTENSIONS: {missing}"

    def test_extension_actually_scanned(self, tmp_path: Path) -> None:
        """Smoke-test: a file with a non-obvious extension is scanned."""
        f = tmp_path / "test.zig"
        f.write_text('const x = "\ufe01";\n')
        assert len(Scanner().scan_file(f)) == 1


# ---------------------------------------------------------------------------
# 8. DEP_SCAN_EXTENSIONS covers multi-language ecosystems
# ---------------------------------------------------------------------------


class TestDepScanExtensions:
    _EXPECTED = {
        ".rs",
        ".go",
        ".java",
        ".kt",
        ".scala",
        ".cs",
        ".swift",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".lua",
        ".dart",
        ".ex",
        ".exs",
        ".erl",
        ".zig",
        ".nim",
        ".ml",
        ".hs",
        ".clj",
        ".jl",
        ".cr",
    }

    def test_all_expected_dep_extensions_present(self) -> None:
        missing = self._EXPECTED - DEP_SCAN_EXTENSIONS
        assert not missing, f"Missing from DEP_SCAN_EXTENSIONS: {missing}"

    def test_scan_deps_finds_vendor_file(self, tmp_path: Path) -> None:
        """Dep scanning picks up source files inside vendor/."""
        pkg = tmp_path / "vendor" / "some-crate"
        pkg.mkdir(parents=True)
        (pkg / "lib.rs").write_text('let x = "\ufe01";\n')
        findings = Scanner(scan_deps=True).scan_path(tmp_path)
        assert any(".rs" in f.file for f in findings)

    def test_scan_deps_includes_target_dir(self, tmp_path: Path) -> None:
        target = tmp_path / "target" / "debug" / "build" / "some-crate"
        target.mkdir(parents=True)
        (target / "lib.rs").write_text('let x = "\ufe01";\n')
        findings = Scanner(scan_deps=True).scan_path(tmp_path)
        assert any("target" in f.file for f in findings)

    def test_target_skipped_without_scan_deps(self, tmp_path: Path) -> None:
        target = tmp_path / "target" / "debug"
        target.mkdir(parents=True)
        (target / "lib.rs").write_text('let x = "\ufe01";\n')
        findings = Scanner(scan_deps=False).scan_path(tmp_path)
        assert not any("target" in f.file for f in findings)


# ---------------------------------------------------------------------------
# 9. Well-known extensionless filenames
# ---------------------------------------------------------------------------


class TestKnownFilenames:
    def test_expected_filenames_in_set(self) -> None:
        expected = {
            "Makefile",
            "Dockerfile",
            "Gemfile",
            "Rakefile",
            "Vagrantfile",
            "Procfile",
            "Justfile",
            "BUILD",
            "Podfile",
            ".gitattributes",
            ".gitignore",
            ".dockerignore",
        }
        missing = expected - KNOWN_FILENAMES
        assert not missing, f"Missing from KNOWN_FILENAMES: {missing}"

    def test_known_filename_actually_scanned(self, tmp_path: Path) -> None:
        """Smoke-test: a Makefile in a directory walk is picked up."""
        (tmp_path / "Makefile").write_text('VAR = "\ufe01"\n')
        findings = Scanner().scan_path(tmp_path)
        assert any("Makefile" in f.file for f in findings)

    def test_unknown_extensionless_file_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "randomfile").write_text('VAR = "\ufe01"\n')
        assert not Scanner().scan_path(tmp_path)

    def test_all_text_scans_extensionless(self, tmp_path: Path) -> None:
        (tmp_path / "randomfile").write_text('VAR = "\ufe01"\n')
        assert Scanner(text_extensions=None).scan_path(tmp_path)


# ---------------------------------------------------------------------------
# 10. target/ classified as dependency (suppression blocked)
# ---------------------------------------------------------------------------


class TestTargetDirClassifiedAsDependency:
    """Files inside target/ must be classified as dependency code so that
    suppression directives are never honored — consistent with node_modules,
    vendor, and site-packages."""

    def test_target_dir_inline_ignore_not_honored(self) -> None:
        scanner = Scanner()
        text = 'let x = "\ufe01"; // heckler-ignore\n'
        findings = scanner.scan_text(text, "target/some-crate/src/lib.rs")
        assert len(findings) == 1
        assert findings[0].codepoint == 0xFE01

    def test_target_dir_next_line_not_honored(self) -> None:
        scanner = Scanner()
        text = '// heckler-ignore-next-line\nlet x = "\u202e";\n'
        findings = scanner.scan_text(text, "target/some-crate/src/lib.rs")
        assert len(findings) == 1
        assert findings[0].codepoint == 0x202E

    def test_target_dir_classified_as_dependency(self) -> None:
        scanner = Scanner()
        text = 'let x = "\ufe01";\n'
        findings = scanner.scan_text(text, "target/some-crate/src/lib.rs")
        assert findings[0].source == "dependency"
        assert findings[0].package == "some-crate"


# ---------------------------------------------------------------------------
# 11. Non-UTF-8 encoding detection (prevents encoding evasion)
# ---------------------------------------------------------------------------


class TestEncodingDetection:
    """Files encoded as UTF-16/32 must be decoded correctly so that
    dangerous codepoints are not missed."""

    def test_utf16_le_bom_detected(self, tmp_path: Path) -> None:
        f = tmp_path / "evil.js"
        f.write_bytes('const x = "\u202e";\n'.encode("utf-16-le"))
        # prepend BOM
        f.write_bytes(b"\xff\xfe" + 'const x = "\u202e";\n'.encode("utf-16-le"))
        findings = Scanner().scan_file(f)
        assert any(fd.codepoint == 0x202E for fd in findings)

    def test_utf16_be_bom_detected(self, tmp_path: Path) -> None:
        f = tmp_path / "evil.js"
        f.write_bytes(b"\xfe\xff" + 'const x = "\u202e";\n'.encode("utf-16-be"))
        findings = Scanner().scan_file(f)
        assert any(fd.codepoint == 0x202E for fd in findings)

    def test_utf32_le_bom_detected(self, tmp_path: Path) -> None:
        f = tmp_path / "evil.js"
        f.write_bytes(b"\xff\xfe\x00\x00" + 'const x = "\u202e";\n'.encode("utf-32-le"))
        findings = Scanner().scan_file(f)
        assert any(fd.codepoint == 0x202E for fd in findings)

    def test_utf8_still_works(self, tmp_path: Path) -> None:
        """Regression: normal UTF-8 files must still be scanned."""
        f = tmp_path / "normal.js"
        f.write_text('const x = "\u202e";\n')
        findings = Scanner().scan_file(f)
        assert len(findings) == 1

    def test_utf16_not_misdetected_as_binary(self, tmp_path: Path) -> None:
        """UTF-16 files contain null bytes — they must NOT be skipped."""
        f = tmp_path / "data.js"
        text = 'let payload = "\ufe0f";\n'
        f.write_bytes(b"\xff\xfe" + text.encode("utf-16-le"))
        findings = Scanner().scan_file(f)
        assert len(findings) == 1
        assert findings[0].codepoint == 0xFE0F


SAMPLE = 'const a = 1;\nconst x = "a\u202eb";\n'


class TestBomThatDoesNotMatchTheContent:
    """A BOM is a claim about the encoding; the bytes after it may disagree."""

    @pytest.mark.parametrize("bom", [b"\xff\xfe", b"\xfe\xff"])
    def test_utf16_bom_on_utf8_text(self, tmp_path: Path, bom: bytes) -> None:
        f = tmp_path / "page.php"
        f.write_bytes(bom + SAMPLE.encode("utf-8"))
        findings = Scanner().scan_file(f)

        assert findings[0].char_name == "Byte order mark for UTF-16 on a file that is not UTF-16"
        assert (findings[0].line, findings[0].column) == (1, 1)
        assert findings[0].severity == Severity.HIGH
        named = [f for f in findings if f.codepoint == 0x202E]
        assert [(f.line, f.char_name) for f in named] == [
            (2, "Right-to-Left Override (read as UTF-8)")
        ]

    def test_utf32_bom_on_utf8_text(self, tmp_path: Path) -> None:
        f = tmp_path / "page.php"
        f.write_bytes(b"\xff\xfe\x00\x00" + SAMPLE.encode("utf-8"))
        findings = Scanner().scan_file(f)
        names = [f.char_name for f in findings]
        assert "Byte order mark for UTF-32 on a file that is not UTF-32" in names
        assert "Right-to-Left Override (read as UTF-8)" in names

    def test_utf32_bom_that_is_a_utf16_bom_and_a_nul(self, tmp_path: Path) -> None:
        """FF FE 00 00 opens a UTF-32 file, and also a UTF-16 one that starts with NUL."""
        f = tmp_path / "script.ps1"
        f.write_bytes(b"\xff\xfe\x00\x00" + SAMPLE.encode("utf-16-le"))
        names = [f.char_name for f in Scanner().scan_file(f)]
        assert "Byte order mark for UTF-32 on a file that is not UTF-32" in names
        assert "Right-to-Left Override (read as UTF-16 LE)" in names

    @pytest.mark.parametrize(
        ("bom", "codec"),
        [
            (b"\xff\xfe", "utf-16-le"),
            (b"\xfe\xff", "utf-16-be"),
            (b"\xff\xfe\x00\x00", "utf-32-le"),
            (b"\x00\x00\xfe\xff", "utf-32-be"),
        ],
    )
    def test_honest_bom_is_read_once(self, tmp_path: Path, bom: bytes, codec: str) -> None:
        f = tmp_path / "evil.js"
        f.write_bytes(bom + SAMPLE.encode(codec))
        findings = Scanner().scan_file(f)
        assert [(f.line, f.char_name) for f in findings] == [(2, "Right-to-Left Override")]

    def test_clean_file_with_an_honest_bom_is_clean(self, tmp_path: Path) -> None:
        f = tmp_path / "ok.js"
        f.write_bytes(b"\xff\xfe" + "const a = 1;\n".encode("utf-16-le"))
        assert Scanner().scan_file(f) == []

    def test_bom_alone_is_not_a_mismatch(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.js"
        f.write_bytes(b"\xff\xfe")
        assert Scanner().scan_file(f) == []

    def test_mismatch_respects_the_severity_threshold(self, tmp_path: Path) -> None:
        f = tmp_path / "page.php"
        f.write_bytes(b"\xff\xfe" + b"const a = 1;\n")
        mismatch = "Byte order mark for UTF-16 on a file that is not UTF-16"
        assert Scanner().scan_file(f)[0].char_name == mismatch
        critical_only = Scanner(severity_threshold=Severity.CRITICAL).scan_file(f)
        assert mismatch not in [f.char_name for f in critical_only]

    def test_every_finding_names_its_reading(self, tmp_path: Path) -> None:
        """Read as UTF-16, "a " is U+2061: noise, and labelled as that reading."""
        f = tmp_path / "page.php"
        f.write_bytes(b"\xff\xfe" + b"const a = 1;\n")
        names = [f.char_name for f in Scanner().scan_file(f)]
        assert names[1:] == ["Function Application (read as UTF-16 LE)"]

    def test_mismatch_fails_ci(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        (tmp_path / "page.php").write_bytes(b"\xff\xfe" + b"<?php echo 1;\n")
        assert main(["--ci", "--no-color", str(tmp_path)]) == 1
        assert "Byte order mark for UTF-16" in capsys.readouterr().out


class TestUtf16WithoutBom:
    """NUL in every other byte is UTF-16; decode it so the real character is named."""

    @pytest.mark.parametrize(
        ("codec", "label"), [("utf-16-le", "UTF-16 LE"), ("utf-16-be", "UTF-16 BE")]
    )
    def test_real_character_is_named(self, tmp_path: Path, codec: str, label: str) -> None:
        f = tmp_path / "evil.js"
        f.write_bytes(SAMPLE.encode(codec))
        findings = Scanner().scan_file(f)
        # Read as UTF-8, all that shows is the NUL bytes.
        assert findings[0].char_name == "Null"
        named = [(f.line, f.column, f.char_name) for f in findings if f.codepoint == 0x202E]
        assert named == [(2, 13, f"Right-to-Left Override (read as {label})")]

    def test_mostly_non_ascii_text_is_still_recognised(self, tmp_path: Path) -> None:
        f = tmp_path / "evil.js"
        text = "// " + "\u0434\u0430\u043d\u043d\u044b\u0435 " * 3 + "\nx = '\u202e';\n"
        f.write_bytes(text.encode("utf-16-le"))
        names = [f.char_name for f in Scanner().scan_file(f)]
        assert "Right-to-Left Override (read as UTF-16 LE)" in names

    @pytest.mark.parametrize(
        "content",
        [
            b"//\x00\n" + b"const p = 1;\n" * 4,
            b"\x00\x00<?php\n$p = 1;\n",
            b"\x00\x01\x02",
            b"x = 1\n" + b"\x00" * 64,
        ],
    )
    def test_stray_nul_bytes_do_not_trigger_it(self, tmp_path: Path, content: bytes) -> None:
        f = tmp_path / "data.js"
        f.write_bytes(content)
        assert not [f for f in Scanner().scan_file(f) if "read as" in f.char_name]

    def test_plain_utf8_is_read_once(self, tmp_path: Path) -> None:
        f = tmp_path / "plain.js"
        f.write_bytes(SAMPLE.encode("utf-8"))
        assert [f.char_name for f in Scanner().scan_file(f)] == ["Right-to-Left Override"]


class TestAllTextInsideDependencies:
    """--all-text means every text file, in a dependency as elsewhere."""

    def _tree(self, tmp_path: Path) -> Path:
        pkg = tmp_path / "node_modules" / "pkg"
        (pkg / "bin").mkdir(parents=True)
        (pkg / "bin" / "cli").write_text("#!/usr/bin/env node\n// \u202e\n", encoding="utf-8")
        (pkg / "notes.weird").write_text("a\u200bb\n", encoding="utf-8")
        (pkg / "logo.png").write_bytes(b"\x89PNG\x00\x00" + b"\xc2\xa0" * 10)
        (pkg / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
        return tmp_path

    def test_extensionless_and_unlisted_files_are_scanned(self, tmp_path: Path) -> None:
        scanner = Scanner(scan_deps=True, text_extensions=None)
        findings = scanner.scan_path(self._tree(tmp_path))
        assert sorted(Path(f.file).name for f in findings) == ["cli", "notes.weird"]

    def test_without_all_text_the_dependency_list_applies(self, tmp_path: Path) -> None:
        assert Scanner(scan_deps=True).scan_path(self._tree(tmp_path)) == []

    def test_cli_flag(self, tmp_path: Path) -> None:
        tree = str(self._tree(tmp_path))
        assert main(["--ci", "--scan-deps", tree]) == 0
        assert main(["--ci", "--scan-deps", "--all-text", tree]) == 1


class TestFileSelection:
    @pytest.mark.parametrize(
        "name",
        [
            "main.cc",
            "main.hh",
            "index.htm",
            "analysis.ipynb",
            "view.html.erb",
            "rule.mdc",
            "Jenkinsfile",
            ".env",
            ".env.example",
            ".env.production",
            ".cursorrules",
            ".windsurfrules",
            ".clinerules",
            "Dockerfile.dev",
            "Dockerfile",
            "api.Dockerfile",
            "worker.mts",
            "worker.cts",
            "hooks.pth",
            "UPPER.JS",
        ],
    )
    def test_scanned_by_default(self, tmp_path: Path, name: str) -> None:
        (tmp_path / name).write_text("x = 'a\u200bb'\n", encoding="utf-8")
        assert len(Scanner().scan_path(tmp_path)) == 1

    @pytest.mark.parametrize("name", ["notes", "data.bin", "Dockerfiles", "env", "x.example"])
    def test_not_scanned_by_default(self, tmp_path: Path, name: str) -> None:
        (tmp_path / name).write_text("x = 'a\u200bb'\n", encoding="utf-8")
        assert Scanner().scan_path(tmp_path) == []

    @pytest.mark.parametrize(
        "name",
        [
            "a.mts",
            "a.cts",
            "a.vue",
            "a.svelte",
            "a.pth",
            "a.ps1",
            "a.bat",
            "a.cc",
            "a.hh",
            "Makefile",
            "Dockerfile.build",
        ],
    )
    def test_scanned_inside_a_dependency(self, tmp_path: Path, name: str) -> None:
        pkg = tmp_path / "node_modules" / "pkg"
        pkg.mkdir(parents=True)
        (pkg / name).write_text("x = 'a\u200bb'\n", encoding="utf-8")
        assert len(Scanner(scan_deps=True).scan_path(tmp_path)) == 1

    def test_dependency_list_is_part_of_the_default_list(self) -> None:
        """A kind of file worth scanning in a dependency is worth scanning in the project."""
        assert sorted(DEP_SCAN_EXTENSIONS - DEFAULT_TEXT_EXTENSIONS) == []

    def test_no_extension_in_the_lists_can_never_match(self) -> None:
        """Path.suffix is the last dotted part only, so '.env.example' is not one."""
        for extension in DEFAULT_TEXT_EXTENSIONS | DEP_SCAN_EXTENSIONS:
            assert Path("name" + extension).suffix == extension, extension
            assert extension == extension.lower(), extension

    def test_walk_order_is_stable(self, tmp_path: Path) -> None:
        for name in ("b.js", "a.js", "c/z.js", "c/a.js", "Z.js"):
            path = tmp_path / name
            path.parent.mkdir(exist_ok=True)
            path.write_text("x = 'a\u200bb'\n", encoding="utf-8")
        files = [
            Path(f.file).relative_to(tmp_path).as_posix() for f in Scanner().scan_path(tmp_path)
        ]
        assert files == ["Z.js", "a.js", "b.js", "c/a.js", "c/z.js"]
