"""Shared test fixtures. Generates test files with dangerous Unicode programmatically
to avoid editors/hooks stripping the characters."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def tmp_scan_dir(tmp_path: Path) -> Path:
    """Create a temp directory with various test files containing dangerous Unicode.

    NOTE: Some fixtures contain strings like 'eval(payload)' to simulate Glassworm
    decoder patterns. These are inert — they exist only as text for the scanner to detect.
    """
    # Clean file — no findings expected
    clean = tmp_path / "clean.js"
    clean.write_text('const x = 1;\nconsole.log("hello world");\n', encoding='utf-8')

    # Glassworm Variation Selectors (CRITICAL)
    glassworm = tmp_path / "glassworm.js"
    # U+FE01 and U+FE0F embedded in a template literal (simulates Glassworm decoder)
    glassworm.write_text(
        'const payload = `\uFE01\uFE0F\uFE03`;\nrun(payload);\n',
        encoding='utf-8',
    )

    # Variation Selectors Supplement (CRITICAL)
    glassworm_supp = tmp_path / "glassworm_supp.js"
    glassworm_supp.write_text(
        'const data = `\U000E0100\U000E0101\U000E01EF`;\n',
        encoding='utf-8',
    )

    # Trojan Source bidi controls (HIGH/CRITICAL)
    bidi = tmp_path / "trojan_source.py"
    bidi.write_text(
        '# Comment with RLO: \u202E reorder\n'
        'access = "\u2066admin\u2069"\n',
        encoding='utf-8',
    )

    # Zero-width characters (MEDIUM)
    zw = tmp_path / "zero_width.ts"
    zw.write_text(
        'const name = "ad\u200Bmin";\n'
        'const val\u200C = 42;\n',
        encoding='utf-8',
    )

    # Tag characters (HIGH)
    tags = tmp_path / "tag_chars.js"
    tags.write_text(
        'const x = "\U000E0020\U000E0041\U000E007F";\n',
        encoding='utf-8',
    )

    # Invisible format chars (MEDIUM/LOW)
    fmt = tmp_path / "invisible_format.ts"
    fmt.write_text(
        'const a = "test\u00ADword";\n'  # Soft hyphen (LOW)
        'const b = 1\u2062 2;\n'          # Invisible Times (MEDIUM)
        'const c = \u3164;\n',            # Hangul Filler (MEDIUM)
        encoding='utf-8',
    )

    # File with heckler-ignore comment
    ignored = tmp_path / "ignored.js"
    ignored.write_text(
        'const safe = "\uFE01"; // heckler-ignore\n'
        'const unsafe = "\uFE02";\n',
        encoding='utf-8',
    )

    # BOM at file start
    bom = tmp_path / "bom_file.js"
    bom.write_text(
        '\uFEFFconst x = 1;\n',
        encoding='utf-8',
    )

    # Binary file (should be skipped)
    binary = tmp_path / "binary.js"
    binary.write_bytes(b'\x00\x01\x02\x03binary content')

    return tmp_path


@pytest.fixture
def glassworm_text() -> str:
    """Text containing Glassworm Variation Selectors."""
    return 'const s = `\uFE00\uFE01\uFE0F`;\nprocess(s);\n'


@pytest.fixture
def bidi_text() -> str:
    """Text containing Trojan Source bidi controls."""
    return 'access = "\u202E\u2066admin\u2069";\n'


@pytest.fixture
def clean_text() -> str:
    """Clean text with no dangerous Unicode."""
    return 'const x = 1;\nconst y = "hello";\n'


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    """Create a .heckler.yml config file."""
    config = tmp_path / ".heckler.yml"
    config.write_text(
        "severity: medium\n"
        "allow_bom: true\n"
        "allowlist:\n"
        "  - '**/*.po'\n"
        "  - '**/locale/**'\n"
        "extra_skip_dirs:\n"
        "  - third_party\n",
        encoding='utf-8',
    )
    return config
