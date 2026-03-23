"""Tests for CLI argument parsing and execution."""

from __future__ import annotations

from pathlib import Path

from heckler.cli import main


class TestCLI:
    def test_clean_directory_returns_0(self, tmp_path: Path) -> None:
        (tmp_path / "clean.js").write_text("const x = 1;\n", encoding="utf-8")
        result = main([str(tmp_path)])
        assert result == 0

    def test_findings_without_ci_returns_0(self, tmp_scan_dir: Path) -> None:
        result = main([str(tmp_scan_dir)])
        assert result == 0

    def test_findings_with_ci_returns_1(self, tmp_scan_dir: Path) -> None:
        result = main(["--ci", str(tmp_scan_dir)])
        assert result == 1

    def test_json_format(self, tmp_scan_dir: Path, capsys: object) -> None:
        import json
        main(["--format", "json", str(tmp_scan_dir)])
        captured = capsys.readouterr()  # type: ignore[attr-defined]
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) > 0
        assert "codepoint" in data[0]

    def test_sarif_format(self, tmp_scan_dir: Path, capsys: object) -> None:
        import json
        main(["--format", "sarif", str(tmp_scan_dir)])
        captured = capsys.readouterr()  # type: ignore[attr-defined]
        sarif = json.loads(captured.out)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert len(sarif["runs"][0]["results"]) > 0

    def test_severity_filter(self, tmp_scan_dir: Path) -> None:
        # With CRITICAL threshold, only variation selectors and RLO should appear
        result = main(["--ci", "--severity", "critical", str(tmp_scan_dir)])
        assert result == 1  # Still has CRITICAL findings

    def test_scan_deps_flag(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text('\uFE01', encoding='utf-8')
        result = main(["--ci", "--scan-deps", str(tmp_path)])
        assert result == 1

    def test_version(self, capsys: object) -> None:
        import pytest
        with pytest.raises(SystemExit, match="0"):  # type: ignore[attr-defined]
            main(["--version"])

    def test_quiet_mode(self, tmp_scan_dir: Path, capsys: object) -> None:
        main(["--quiet", str(tmp_scan_dir)])
        captured = capsys.readouterr()  # type: ignore[attr-defined]
        # Quiet mode should not include summary lines
        assert "Total:" not in captured.out
