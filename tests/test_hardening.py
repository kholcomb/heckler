"""Tests for threat-model hardening fixes.

Covers: U+2028/2029 detection, heckler-ignore comment enforcement,
null-byte injection resistance, missing --config error, unsupported
ecosystem warnings, and zip member filtering.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from heckler.characters import DANGEROUS_UNICODE_RE, Severity, ThreatCategory, get_char_info
from heckler.cli import main
from heckler.config import load_config
from heckler.lockfile import parse_changed_packages
from heckler.scanner import Scanner
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
# 2. heckler-ignore comment enforcement
# ---------------------------------------------------------------------------

class TestIgnoreCommentHardening:
    def test_js_comment_still_works(self) -> None:
        scanner = Scanner()
        text = 'const x = "\uFE01"; // heckler-ignore\n'
        assert scanner.scan_text(text) == []

    def test_python_comment_still_works(self) -> None:
        scanner = Scanner()
        text = 'x = "\uFE01"  # heckler-ignore\n'
        assert scanner.scan_text(text) == []

    def test_sql_comment_still_works(self) -> None:
        scanner = Scanner()
        text = 'SELECT "\uFE01"; -- heckler-ignore\n'
        assert scanner.scan_text(text) == []

    def test_block_comment_still_works(self) -> None:
        scanner = Scanner()
        text = 'const x = "\uFE01"; /* heckler-ignore */\n'
        assert scanner.scan_text(text) == []

    def test_semicolon_comment_still_works(self) -> None:
        scanner = Scanner()
        text = 'key = "\uFE01" ; heckler-ignore\n'
        assert scanner.scan_text(text) == []

    def test_string_literal_does_not_suppress(self) -> None:
        """An adversary placing heckler-ignore inside a string should NOT
        suppress detection of dangerous chars on the same line."""
        scanner = Scanner()
        text = 'x = "heckler-ignore"; auth = "\u202E"\n'
        findings = scanner.scan_text(text)
        assert len(findings) >= 1
        assert any(f.codepoint == 0x202E for f in findings)

    def test_variable_name_does_not_suppress(self) -> None:
        scanner = Scanner()
        text = 'heckler_ignore = "\uFE01"\n'
        findings = scanner.scan_text(text)
        assert len(findings) == 1

    def test_partial_match_does_not_suppress(self) -> None:
        scanner = Scanner()
        text = 'msg = "run heckler-ignore check \uFE01"\n'
        findings = scanner.scan_text(text)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# 3. Null-byte injection resistance
# ---------------------------------------------------------------------------

class TestNullByteHardening:
    def test_null_after_dangerous_chars_still_detected(self, tmp_path: Path) -> None:
        """Dangerous chars before a null byte should still be found."""
        f = tmp_path / "tricky.js"
        content = 'const x = "\uFE01";\n'.encode('utf-8') + b'\x00binary stuff'
        f.write_bytes(content)

        scanner = Scanner()
        findings = scanner.scan_file(f)
        assert len(findings) == 1
        assert findings[0].codepoint == 0xFE01

    def test_null_at_start_skips_file(self, tmp_path: Path) -> None:
        """A file starting with null is genuinely binary — skip it."""
        f = tmp_path / "binary.js"
        f.write_bytes(b'\x00\x01\x02')
        scanner = Scanner()
        assert scanner.scan_file(f) == []

    def test_null_byte_midfile_scans_prefix(self, tmp_path: Path) -> None:
        """Dangerous chars in the text portion before null should be found."""
        f = tmp_path / "mixed.js"
        evil = 'line1 \u200B ok\nline2 \u202E bad\n'.encode('utf-8')
        f.write_bytes(evil + b'\x00' + b'binary tail')
        scanner = Scanner()
        findings = scanner.scan_file(f)
        assert len(findings) == 2


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
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("pkg/index.js", b'module.exports = {};')
            zf.writestr("pkg/lib/util.js", b'exports.x = 1;')

        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        _safe_zip_extract(zip_path, extract_dir, extract_dir.resolve())

        assert (extract_dir / "pkg" / "index.js").exists()
        assert (extract_dir / "pkg" / "lib" / "util.js").exists()

    def test_wheel_with_planted_chars_detected(self, tmp_path: Path) -> None:
        """End-to-end: a .whl with dangerous chars is extracted and scanned."""
        evil_py = 'access = "\u202Eadmin"\n'.encode()
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
    @pytest.mark.parametrize("ext", [".ps1", ".bat", ".cmd", ".fish", ".ejs",
                                      ".hbs", ".gradle", ".proto", ".graphql"])
    def test_new_extensions_scanned(self, tmp_path: Path, ext: str) -> None:
        f = tmp_path / f"test{ext}"
        f.write_text('payload = "\uFE01"\n', encoding='utf-8')
        scanner = Scanner()
        findings = scanner.scan_file(f)
        assert len(findings) == 1

    @pytest.mark.parametrize("ext", [
        ".dart", ".ex", ".exs", ".erl", ".hrl", ".zig", ".nim",
        ".ml", ".mli", ".hs", ".lhs", ".clj", ".cljs", ".cljc",
        ".jl", ".elm", ".v", ".d", ".ada", ".adb", ".ads",
        ".f90", ".groovy", ".cr", ".purs", ".rkt",
        ".lisp", ".cl", ".el", ".asm", ".s",
        ".m", ".mm", ".vb", ".vbs", ".pp", ".pas", ".tcl",
    ])
    def test_modern_language_extensions_scanned(self, tmp_path: Path, ext: str) -> None:
        f = tmp_path / f"test{ext}"
        f.write_text('payload = "\uFE01"\n', encoding='utf-8')
        scanner = Scanner()
        findings = scanner.scan_file(f)
        assert len(findings) == 1, f"Extension {ext} was not scanned"
