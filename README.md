# heckler

Zero-dependency Python tool that detects dangerous invisible Unicode characters in source code and dependencies. Covers 414 codepoints across 6 threat categories including Glassworm supply chain attacks (Variation Selectors), Trojan Source (bidi controls, CVE-2021-42574), zero-width steganography, tag character injection, and exotic whitespace.

## Install

```bash
pip install heckler
```

Requires Python 3.9+. No runtime dependencies.

## Quick Start

```bash
# Scan a directory
heckler .

# CI mode — exit code 1 on findings
heckler --ci .

# Include node_modules / site-packages / vendor
heckler --ci --scan-deps .

# Vet a package before installing
heckler --vet express@4.18.0
heckler --vet requests==2.31.0

# JSON or SARIF output
heckler --format json .
heckler --format sarif .
```

## What It Detects

| Category | Codepoints | Severity | Example |
|---|---|---|---|
| Variation Selectors (Glassworm) | U+FE00-FE0F, U+E0100-E01EF, U+180B-180D | CRITICAL/HIGH | Invisible payload encoding |
| Bidi controls (Trojan Source) | U+202A-202E, U+2066-2069, U+200E-200F, U+061C | CRITICAL/HIGH | Code displays differently than it executes |
| Tag characters | U+E0001, U+E0020-E007F | HIGH | Invisible ASCII mirror used in prompt injection |
| Zero-width characters | U+200B-200D, U+FEFF, U+2060 | MEDIUM | Steganographic encoding, string comparison bypass |
| Invisible identifiers | U+3164, U+FFA0, U+2800, U+115F-1160 | MEDIUM | Invisible variable/function names |
| Invisible format/whitespace | U+00AD, U+2000-200A, U+2061-2064, U+3000, ... | LOW-MEDIUM | String comparison bypass, obfuscation |

414 codepoints total. Severity levels: CRITICAL > HIGH > MEDIUM > LOW > INFO.

## CLI Reference

```
heckler [paths...] [options]
heckler --vet PACKAGE [--registry npm|pypi]
```

| Flag | Description |
|---|---|
| `--ci` | Exit code 1 if findings detected |
| `--format text\|json\|sarif` | Output format (default: text) |
| `--severity LEVEL` | Minimum severity to report (default: low) |
| `--scan-deps` | Include dependency directories |
| `--diff-only` | With `--scan-deps`, only scan packages changed in staged lockfile diffs |
| `--vet PACKAGE` | Download and scan a package before installing |
| `--registry npm\|pypi` | Package registry for `--vet` (auto-detected if omitted) |
| `--config PATH` | Path to `.heckler.yml` config file |
| `--no-color` | Disable colored output |
| `--quiet` | Only output findings, no summary |
| `--all-text` | Scan all text files regardless of extension |

Exit codes: `0` clean, `1` findings detected (with `--ci`), `2` error.

## Library API

```python
from heckler import scan, Scanner, Finding

# Simple: scan a path
findings = scan("src/")

# Advanced: configure a scanner
scanner = Scanner(scan_deps=True, severity_threshold=Severity.HIGH)
findings = scanner.scan_text(some_string, filename="input.js")
findings = scanner.scan_file(Path("app.js"))
findings = scanner.scan_path(Path("project/"))
```

## Configuration

Create `.heckler.yml` in your project root:

```yaml
severity: medium           # Minimum severity to report
allow_bom: true            # Treat U+FEFF at file start as INFO (suppressed)

allowlist:                 # Glob patterns for files to skip
  - "**/*.po"
  - "**/locale/**"

extra_skip_dirs:           # Additional directories to skip
  - third_party

extra_extensions:          # Additional file extensions to scan
  - .custom
```

Also reads `[tool.heckler]` from `pyproject.toml`.

Suppress individual lines with an inline comment:

```javascript
const emoji = "\uFE0F"; // heckler-ignore
```

## CI/CD Integration

### GitHub Actions

Use as a composite action:

```yaml
- uses: heckler/heckler@v1
  with:
    scan-deps: true
    format: sarif
    upload-sarif: true  # Findings appear in GitHub Security tab
```

Or invoke directly:

```yaml
- run: pip install heckler
- run: heckler --ci --format sarif . > results.sarif
```

### Pre-commit

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/heckler/heckler
    rev: v0.1.0
    hooks:
      - id: heckler          # Scan source files
      - id: heckler-lockfile         # Scan changed dependencies on lockfile change
```

### Dependency Scanning Workflow

A separate workflow (`dependency-scan.yml`) triggers on lockfile changes and weekly, auto-detects your package manager, installs dependencies, scans them, and reports findings in the GitHub Actions job summary. Results are cached by lockfile hash.

## Defense-in-Depth

| Layer | When | Speed | What it catches |
|---|---|---|---|
| `--vet` | Before `npm add` / `pip install` | ~5s | Malicious packages before they enter your project |
| Pre-commit (source) | `git commit` | <2s | Invisible chars in your own code |
| Pre-commit (lockfile) | Lockfile change + commit | <2s | Changed deps via diff-based scanning |
| CI source scan | PR / push | <5s | Source scan, enforceable |
| CI dep scan | Lockfile change + weekly | 30-60s (cached: 5s) | Full dependency tree post-install |

## Shell Script (Zero Dependencies)

For environments without Python, a grep-based fallback is included:

```bash
bash scripts/heckler-scan.sh [directory]
```

Requires GNU grep with PCRE support (`grep -P`). macOS users: `brew install grep`.

## Testing

105 tests, zero mocks. Every test exercises real code paths with real Unicode data on real files.

```bash
pip install -e ".[dev]"
pytest
```

The test suite includes:

- **Character detection** — verifies the regex matches every dangerous codepoint and rejects safe ones
- **Scanner** — writes real files with planted invisible Unicode to temp directories and scans them
- **CLI** — calls `main()` with real argv, validates JSON/SARIF output structure
- **Config** — writes real `.heckler.yml` files and loads them through the config pipeline
- **Archive safety** — builds malicious tar/zip archives with path traversal and symlink attacks, verifies they're rejected
- **Vet end-to-end** — builds fake `.tgz` and `.whl` packages with planted Glassworm signatures, extracts and scans them
- **Git integration** — stages a real lockfile in the project repo, parses the diff, resolves package directories, and scans planted findings through the full `--diff-only` chain (non-destructive, cleanup in `finally` blocks)

## License

MIT
