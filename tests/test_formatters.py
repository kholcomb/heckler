"""Tests for output formatters."""

from __future__ import annotations

import json

from heckler.characters import Severity, ThreatCategory
from heckler.formatters import format_json, format_sarif, format_text
from heckler.scanner import Finding


def _make_finding(**kwargs: object) -> Finding:
    defaults = {
        "file": "test.js",
        "line": 1,
        "column": 5,
        "codepoint": 0xFE01,
        "codepoint_hex": "U+FE01",
        "char_name": "Variation Selector 2",
        "category": ThreatCategory.VARIATION_SELECTOR,
        "severity": Severity.CRITICAL,
        "line_content": 'const x = "";\n',
        "source": "project",
        "package": None,
    }
    defaults.update(kwargs)
    return Finding(**defaults)  # type: ignore[arg-type]


class TestTextFormatter:
    def test_no_findings(self) -> None:
        output = format_text([], color=False)
        assert "No dangerous" in output

    def test_findings_present(self) -> None:
        findings = [_make_finding()]
        output = format_text(findings, color=False)
        assert "U+FE01" in output
        assert "CRITICAL" in output
        assert "GLASSWORM" in output

    def test_bidi_tag(self) -> None:
        finding = _make_finding(
            category=ThreatCategory.BIDI_CONTROL,
            severity=Severity.HIGH,
            char_name="Right-to-Left Override",
        )
        output = format_text([finding], color=False)
        assert "TROJAN-SOURCE" in output

    def test_dependency_package_shown(self) -> None:
        finding = _make_finding(source="dependency", package="evil-pkg")
        output = format_text([finding], color=False)
        assert "pkg:evil-pkg" in output

    def test_quiet_suppresses_summary(self) -> None:
        output = format_text([_make_finding()], color=False, quiet=True)
        assert "Total:" not in output


class TestJsonFormatter:
    def test_valid_json(self) -> None:
        findings = [_make_finding()]
        output = format_json(findings)
        data = json.loads(output)
        assert isinstance(data, list)
        assert len(data) == 1

    def test_finding_fields(self) -> None:
        output = format_json([_make_finding()])
        data = json.loads(output)[0]
        assert data["codepoint"] == "U+FE01"
        assert data["severity"] == "critical"
        assert data["category"] == "variation_selector"

    def test_empty_findings(self) -> None:
        output = format_json([])
        assert json.loads(output) == []


class TestSarifFormatter:
    def test_valid_sarif_structure(self) -> None:
        findings = [_make_finding()]
        output = format_sarif(findings)
        sarif = json.loads(output)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert "heckler" in run["tool"]["driver"]["name"]
        assert len(run["results"]) == 1

    def test_sarif_severity_mapping(self) -> None:
        findings = [
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(
                severity=Severity.MEDIUM,
                codepoint=0x200B,
                codepoint_hex="U+200B",
                category=ThreatCategory.ZERO_WIDTH,
                char_name="ZWSP",
            ),
        ]
        output = format_sarif(findings)
        sarif = json.loads(output)
        levels = [r["level"] for r in sarif["runs"][0]["results"]]
        assert "error" in levels
        assert "warning" in levels

    def test_sarif_rules_match_findings(self) -> None:
        findings = [_make_finding()]
        output = format_sarif(findings)
        sarif = json.loads(output)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "glassworm/variation-selector"

    def test_empty_findings(self) -> None:
        output = format_sarif([])
        sarif = json.loads(output)
        assert sarif["runs"][0]["results"] == []
