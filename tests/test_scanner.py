"""Tests for the core scanner."""

from __future__ import annotations

from pathlib import Path

from heckler.characters import Severity, ThreatCategory
from heckler.scanner import Scanner


class TestScanText:
    def test_clean_text(self, clean_text: str) -> None:
        scanner = Scanner()
        findings = scanner.scan_text(clean_text)
        assert findings == []

    def test_glassworm_variation_selectors(self, glassworm_text: str) -> None:
        scanner = Scanner()
        findings = scanner.scan_text(glassworm_text)
        assert len(findings) == 3
        assert all(f.severity == Severity.CRITICAL for f in findings)
        assert all(f.category == ThreatCategory.VARIATION_SELECTOR for f in findings)

    def test_bidi_controls(self, bidi_text: str) -> None:
        scanner = Scanner()
        findings = scanner.scan_text(bidi_text)
        assert len(findings) >= 2
        categories = {f.category for f in findings}
        assert ThreatCategory.BIDI_CONTROL in categories

    def test_inline_ignore(self) -> None:
        scanner = Scanner()
        text = 'const x = "\uFE01"; // heckler-ignore\n'
        findings = scanner.scan_text(text)
        assert findings == []

    def test_bom_at_start_allowed(self) -> None:
        scanner = Scanner(allow_bom=True)
        text = '\uFEFFconst x = 1;\n'
        findings = scanner.scan_text(text)
        assert findings == []

    def test_bom_at_start_disallowed(self) -> None:
        scanner = Scanner(allow_bom=False)
        text = '\uFEFFconst x = 1;\n'
        findings = scanner.scan_text(text)
        assert len(findings) == 1

    def test_bom_not_at_start(self) -> None:
        scanner = Scanner()
        text = 'const x = "\uFEFF";\n'
        findings = scanner.scan_text(text)
        assert len(findings) == 1

    def test_severity_threshold(self) -> None:
        scanner = Scanner(severity_threshold=Severity.HIGH)
        # LOW severity char (soft hyphen) should be filtered
        text = 'const x = "test\u00ADword";\n'
        findings = scanner.scan_text(text)
        assert findings == []

    def test_severity_threshold_passes_high(self) -> None:
        scanner = Scanner(severity_threshold=Severity.HIGH)
        text = 'const x = "\u202E";\n'  # RLO = CRITICAL
        findings = scanner.scan_text(text)
        assert len(findings) == 1

    def test_finding_metadata(self, glassworm_text: str) -> None:
        scanner = Scanner()
        findings = scanner.scan_text(glassworm_text, "test.js")
        assert findings[0].file == "test.js"
        assert findings[0].line == 1
        assert findings[0].column > 0
        assert findings[0].codepoint_hex.startswith("U+")

    def test_multiple_findings_per_line(self) -> None:
        scanner = Scanner()
        text = '\u200B\u200C\u200D\n'
        findings = scanner.scan_text(text)
        assert len(findings) == 3


class TestScanFile:
    def test_scan_file(self, tmp_scan_dir: Path) -> None:
        scanner = Scanner()
        findings = scanner.scan_file(tmp_scan_dir / "glassworm.js")
        assert len(findings) == 3
        assert all(f.severity == Severity.CRITICAL for f in findings)

    def test_skip_binary_file(self, tmp_scan_dir: Path) -> None:
        scanner = Scanner()
        findings = scanner.scan_file(tmp_scan_dir / "binary.js")
        assert findings == []

    def test_clean_file(self, tmp_scan_dir: Path) -> None:
        scanner = Scanner()
        findings = scanner.scan_file(tmp_scan_dir / "clean.js")
        assert findings == []


class TestScanPath:
    def test_scan_directory(self, tmp_scan_dir: Path) -> None:
        scanner = Scanner()
        findings = scanner.scan_path(tmp_scan_dir)
        # Should find chars in glassworm.js, glassworm_supp.js, trojan_source.py,
        # zero_width.ts, tag_chars.js, invisible_format.ts, ignored.js (line 2 only)
        assert len(findings) > 10
        # Should NOT find in clean.js or binary.js
        files_with_findings = {f.file for f in findings}
        assert not any("clean.js" in f for f in files_with_findings)
        assert not any("binary.js" in f for f in files_with_findings)

    def test_skip_dirs(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules" / "evil"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text('\uFE01', encoding='utf-8')
        # Also create a project file
        (tmp_path / "app.js").write_text('clean', encoding='utf-8')

        scanner = Scanner()
        findings = scanner.scan_path(tmp_path)
        assert not any("node_modules" in f.file for f in findings)

    def test_scan_deps(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules" / "evil"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text('\uFE01', encoding='utf-8')

        scanner = Scanner(scan_deps=True)
        findings = scanner.scan_path(tmp_path)
        assert any("node_modules" in f.file for f in findings)
        dep_findings = [f for f in findings if f.source == "dependency"]
        assert len(dep_findings) == 1
        assert dep_findings[0].package == "evil"

    def test_scan_deps_scoped_package(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules" / "@scope" / "pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text('\u202E', encoding='utf-8')

        scanner = Scanner(scan_deps=True)
        findings = scanner.scan_path(tmp_path)
        dep_findings = [f for f in findings if f.source == "dependency"]
        assert dep_findings[0].package == "@scope/pkg"

    def test_exclude_patterns(self, tmp_path: Path) -> None:
        (tmp_path / "include.js").write_text('\uFE01', encoding='utf-8')
        (tmp_path / "exclude.po").write_text('\uFE01', encoding='utf-8')

        scanner = Scanner(exclude_patterns=["*.po"])
        findings = scanner.scan_path(tmp_path)
        assert any("include.js" in f.file for f in findings)
        assert not any("exclude.po" in f.file for f in findings)
