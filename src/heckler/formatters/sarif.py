"""SARIF v2.1.0 formatter for GitHub Security tab integration."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..scanner import Finding

from .._version import __version__
from ..characters import Severity, ThreatCategory

_SEVERITY_TO_SARIF = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_CATEGORY_RULES = {
    ThreatCategory.VARIATION_SELECTOR: {
        "id": "glassworm/variation-selector",
        "name": "GlasswormVariationSelector",
        "shortDescription": {"text": "Glassworm Variation Selector encoding detected"},
        "fullDescription": {
            "text": "Variation Selector characters (U+FE00-FE0F, U+E0100-E01EF) used by the "
            "Glassworm supply chain worm to encode invisible malicious payloads."
        },
        "helpUri": "https://trojansource.codes/",
        "properties": {"tags": ["security", "supply-chain", "glassworm"]},
    },
    ThreatCategory.BIDI_CONTROL: {
        "id": "glassworm/bidi-control",
        "name": "TrojanSourceBidiControl",
        "shortDescription": {"text": "Bidirectional text control character detected"},
        "fullDescription": {
            "text": "Bidi override/isolate characters (CVE-2021-42574) cause displayed code "
            "to diverge from executed code."
        },
        "helpUri": "https://trojansource.codes/",
        "properties": {"tags": ["security", "trojan-source", "CVE-2021-42574"]},
    },
    ThreatCategory.TAG_CHARACTER: {
        "id": "glassworm/tag-character",
        "name": "InvisibleTagCharacter",
        "shortDescription": {"text": "Invisible Unicode tag character detected"},
        "fullDescription": {
            "text": "Tag characters (U+E0001, U+E0020-E007F) mirror ASCII but render invisible. "
            "Used in AI prompt injection and supply chain attacks."
        },
        "helpUri": "https://trojansource.codes/",
        "properties": {"tags": ["security", "tag-character"]},
    },
    ThreatCategory.ZERO_WIDTH: {
        "id": "glassworm/zero-width",
        "name": "ZeroWidthCharacter",
        "shortDescription": {"text": "Zero-width character detected"},
        "fullDescription": {
            "text": "Zero-width characters (ZWSP, ZWNJ, ZWJ, BOM, Word Joiner) are invisible "
            "and can be used for steganographic encoding or string comparison bypasses."
        },
        "helpUri": "https://trojansource.codes/",
        "properties": {"tags": ["security", "zero-width"]},
    },
    ThreatCategory.INVISIBLE_FORMAT: {
        "id": "glassworm/invisible-format",
        "name": "InvisibleFormatCharacter",
        "shortDescription": {"text": "Invisible format/operator character detected"},
        "fullDescription": {
            "text": "Invisible mathematical operators, deprecated format characters, or "
            "other non-rendering Unicode that may hide malicious intent."
        },
        "helpUri": "https://trojansource.codes/",
        "properties": {"tags": ["security", "invisible-format"]},
    },
    ThreatCategory.INVISIBLE_IDENTIFIER: {
        "id": "glassworm/invisible-identifier",
        "name": "InvisibleIdentifier",
        "shortDescription": {"text": "Invisible identifier character detected"},
        "fullDescription": {
            "text": "Characters like Hangul Filler (U+3164) and Braille Blank (U+2800) can "
            "form valid but invisible variable names in JavaScript and other languages."
        },
        "helpUri": "https://trojansource.codes/",
        "properties": {"tags": ["security", "invisible-identifier"]},
    },
}


def format_sarif(findings: list[Finding], **kwargs: object) -> str:
    """Format findings as SARIF v2.1.0 JSON."""
    # Collect which rules are actually used
    used_categories = {f.category for f in findings}
    rules = [_CATEGORY_RULES[cat] for cat in ThreatCategory if cat in used_categories]
    rule_index = {
        cat: i
        for i, cat in enumerate(cat for cat in ThreatCategory if cat in used_categories)
    }

    results = []
    for f in findings:
        result: dict[str, object] = {
            "ruleId": _CATEGORY_RULES[f.category]["id"],
            "ruleIndex": rule_index[f.category],
            "level": _SEVERITY_TO_SARIF[f.severity],
            "message": {
                "text": f"{f.codepoint_hex} ({f.char_name}) — {f.severity.value.upper()} severity"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": f.line,
                            "startColumn": f.column,
                        },
                    }
                }
            ],
        }
        if f.package:
            result["properties"] = {"package": f.package, "source": f.source}
        results.append(result)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "heckler",
                        "version": __version__,
                        "informationUri": "https://github.com/kholcomb/heckler",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    return json.dumps(sarif, indent=2, ensure_ascii=False)
