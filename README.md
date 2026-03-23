<p align="center">
  <img src="docs/assets/heckler-logo.png" alt="Heckler" width="300">
</p>

<p align="center">

[![CI](https://github.com/kholcomb/heckler/actions/workflows/ci.yml/badge.svg)](https://github.com/kholcomb/heckler/actions/workflows/ci.yml) [![PyPI version](https://img.shields.io/pypi/v/heckler)](https://pypi.org/project/heckler/) [![GitHub Marketplace](https://img.shields.io/badge/Marketplace-HecklerDetection-blue?logo=github)](https://github.com/marketplace/actions/hecklerdetection)

</p>

# Heckler

Zero-dependency Python tool that detects dangerous invisible Unicode characters in source code and dependencies. Language-agnostic source scanning covers 60+ file extensions and well-known extensionless files (Makefile, Dockerfile, etc.) across all major ecosystems. Provides coverage on 416 codepoints across 6 threat categories including Glassworm supply chain attacks (Variation Selectors), Trojan Source (bidi controls, CVE-2021-42574), zero-width steganography, tag character injection, and exotic whitespace.

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

## Example

```
$ heckler suspect-project/

Found 6 dangerous character(s): 3 CRITICAL, 1 HIGH, 1 MEDIUM, 1 LOW

suspect-project/api.js
  12:8   CRITICAL  U+FE01 (VARIATION SELECTOR-2) [GLASSWORM]
  12:14  CRITICAL  U+FE02 (VARIATION SELECTOR-3) [GLASSWORM]

suspect-project/auth.js
  4:5    CRITICAL  U+202E (RIGHT-TO-LEFT OVERRIDE) [TROJAN-SOURCE]
  4:32   HIGH      U+202C (POP DIRECTIONAL FORMATTING) [TROJAN-SOURCE]

suspect-project/config.py
  9:22   MEDIUM    U+200B (ZERO WIDTH SPACE)
  18:5   LOW       U+00AD (SOFT HYPHEN)

Total: 6 finding(s) across 3 file(s).
```

## What It Detects

| Category | Codepoints | Severity | Example |
|---|---|---|---|
| Variation Selectors (Glassworm) | U+FE00-FE0F, U+E0100-E01EF, U+180B-180D | CRITICAL/HIGH | Invisible payload encoding |
| Bidi controls (Trojan Source) | U+202A-202E, U+2066-2069, U+2028-2029, U+200E-200F, U+061C | CRITICAL/HIGH | Code displays differently than it executes |
| Tag characters | U+E0001, U+E0020-E007F | HIGH | Invisible ASCII mirror used in prompt injection |
| Zero-width characters | U+200B-200D, U+FEFF, U+2060 | MEDIUM | Steganographic encoding, string comparison bypass |
| Invisible identifiers | U+3164, U+FFA0, U+2800, U+115F-1160 | MEDIUM | Invisible variable/function names |
| Invisible format/whitespace | U+00AD, U+2000-200A, U+2061-2064, U+3000, ... | LOW-MEDIUM | String comparison bypass, obfuscation |

416 codepoints total. Severity levels: CRITICAL > HIGH > MEDIUM > LOW > INFO.

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
| `--vet PACKAGE` | Download and scan a package before installing (fetches directly from public registries) |
| `--registry npm\|pypi` | Package registry for `--vet` (auto-detected if omitted) |
| `--config PATH` | Path to `.heckler.yml` config file (error if not found) |
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

Suppress the next line with a dedicated directive (preferred):

```javascript
// heckler-ignore-next-line
const emoji = "\uFE0F";

// heckler-ignore-next-line U+FE0F U+FE0E
const selectors = "\uFE0F\uFE0E";  // only listed codepoints suppressed
```

Or suppress inline (legacy, still supported):

```javascript
const emoji = "\uFE0F"; // heckler-ignore
```

```python
emoji = "\uFE0F"  # heckler-ignore
```

Supported comment tokens: `//`, `#`, `/*`, `--`, `;`. Placing `heckler-ignore` inside a string literal or variable name does **not** suppress detection. Suppression directives are **never honored in dependency code** (node\_modules, vendor, site-packages, target) to prevent malicious packages from hiding attacks.

## Language Support

Source scanning is **language-agnostic** — the regex-based detector works on any text file. Files encoded as UTF-16 or UTF-32 (with BOM) are automatically detected and decoded correctly. Out of the box, heckler scans 60+ file extensions:

| Category | Extensions |
|---|---|
| Web / JS / TS | `.js`, `.cjs`, `.mjs`, `.ts`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| Python | `.py`, `.pyi` |
| Systems | `.c`, `.cpp`, `.h`, `.hpp`, `.rs`, `.go`, `.zig`, `.nim`, `.d` |
| JVM | `.java`, `.kt`, `.scala`, `.groovy`, `.clj`, `.cljs`, `.cljc` |
| .NET | `.cs`, `.vb`, `.vbs` |
| Functional | `.hs`, `.lhs`, `.ml`, `.mli`, `.elm`, `.ex`, `.exs`, `.erl`, `.hrl`, `.purs`, `.rkt`, `.lisp`, `.cl`, `.el`, `.jl` |
| Mobile | `.swift`, `.dart`, `.m`, `.mm` |
| Scripting | `.rb`, `.php`, `.lua`, `.pl`, `.r`, `.tcl`, `.cr` |
| Shell | `.sh`, `.bash`, `.zsh`, `.ps1`, `.bat`, `.cmd`, `.fish` |
| Config / Data | `.yaml`, `.yml`, `.json`, `.toml`, `.xml`, `.sql`, `.graphql`, `.gql`, `.proto`, `.tf`, `.hcl` |
| Templates | `.html`, `.css`, `.scss`, `.ejs`, `.hbs`, `.njk`, `.pug`, `.jinja` |
| Build | `.gradle`, `.rake`, `.cmake`, `.mk` |
| Docs | `.md`, `.txt` |

Well-known extensionless files are also scanned: `Makefile`, `Dockerfile`, `Gemfile`, `Rakefile`, `Vagrantfile`, `Procfile`, `Justfile`, `BUILD`, `Podfile`, `.gitignore`, `.dockerignore`, and more.

Use `--all-text` to scan every text file regardless of extension.

### Dependency / Supply Chain Coverage

| Capability | Supported Ecosystems |
|---|---|
| `--vet` (pre-install scan) | npm, PyPI |
| `--diff-only` (lockfile parsing) | npm, yarn, pnpm, pip, poetry |
| `--scan-deps` (installed deps) | node\_modules, vendor, site-packages, target (Cargo) |

Lockfiles for Cargo, Go, Ruby, and Composer are detected but parsers are not yet implemented — a warning is emitted when using `--diff-only` with these.

> **Private registries:** `--vet` fetches packages directly from the public npm and PyPI registries (`registry.npmjs.org`, `pypi.org`) using only Python's stdlib — it does **not** shell out to `npm` or `pip` and does **not** execute any package code during download. This means private or corporate registries are not supported by `--vet`. If you need to scan packages from a private registry, download them manually and use `heckler <path>` to scan the extracted source.

## CI/CD Integration

### GitHub Actions

Available on the [GitHub Marketplace](https://github.com/marketplace/actions/hecklerdetection). Use as a composite action:

```yaml
- uses: kholcomb/heckler@v1
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
  - repo: https://github.com/kholcomb/heckler
    rev: v1.0.0
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

```bash
pip install -e ".[dev]"
pytest
```

The test suite includes:

- **Character detection** — verifies the regex matches every dangerous codepoint and rejects safe ones
- **Scanner** — writes real files with **benign** planted invisible Unicode to temp directories and scans them
- **CLI** — calls `main()` with real argv, validates JSON/SARIF output structure
- **Config** — writes real `.heckler.yml` files and loads them through the config pipeline
- **Archive safety** — builds tar/zip archives with path traversal and symlink style payloads, verifies they're safely rejected
- **Vet end-to-end** — builds fake `.tgz` and `.whl` packages with planted Glassworm signatures, extracts and scans them
- **Git integration** — stages a real lockfile in the project repo, parses the diff, resolves package directories, and scans planted findings through the full `--diff-only` chain (non-destructive, cleanup in `finally` blocks)
- **Hardening** — tests for bypass resistance including null-byte injection, heckler-ignore abuse, U+2028/2029 detection, UTF-16/32 encoding evasion, missing config errors, multi-language extension coverage, and extensionless file scanning

## License

MIT
