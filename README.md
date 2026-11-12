<p align="center">
  <img src="docs/assets/heckler-logo.png" alt="Heckler" width="300">
</p>

<p align="center">

[![CI](https://github.com/kholcomb/heckler/actions/workflows/ci.yml/badge.svg)](https://github.com/kholcomb/heckler/actions/workflows/ci.yml) [![PyPI version](https://img.shields.io/pypi/v/heckler)](https://pypi.org/project/heckler/) [![GitHub Marketplace](https://img.shields.io/badge/Marketplace-HecklerDetection-blue?logo=github)](https://github.com/marketplace/actions/hecklerdetection)

</p>

# Heckler

Zero-dependency Python tool that detects dangerous invisible Unicode characters in source code and dependencies. It scans every text file, whatever it is written in. Provides coverage on 4,263 codepoints across 7 threat categories including Glassworm supply chain attacks (Variation Selectors), Trojan Source (bidi controls, CVE-2021-42574), zero-width steganography, tag character injection, control characters, and exotic whitespace.

## Install

```bash
pip install heckler
```

Requires Python 3.11+. No runtime dependencies.

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
  3:18  CRITICAL  U+FE01 (Variation Selector 2) [GLASSWORM]
  3:19  CRITICAL  U+FE02 (Variation Selector 3) [GLASSWORM]
      const label = "v2<U+FE01><U+FE02>";

suspect-project/auth.js
  2:25  CRITICAL  U+202E (Right-to-Left Override) [TROJAN-SOURCE]
  2:31  HIGH  U+202C (Pop Directional Formatting) [TROJAN-SOURCE]
      const role = "user"; // <U+202E>nimda<U+202C>

suspect-project/config.py
  1:11  MEDIUM  U+200B (Zero Width Space)
      name = "ad<U+200B>min"
  2:12  LOW  U+00AD (Soft Hyphen)
      title = "co<U+00AD>operate"

Total: 6 finding(s) across 3 file(s).
```

In the text report, the findings on a source line are followed by that line with every invisible character spelled out. Long lines are cut to a window around the finding. The example is the tool's real output for a small fixture; a test fails if the two drift apart.

## What It Detects

| Category | Codepoints | Severity | Example |
|---|---|---|---|
| Variation Selectors (Glassworm) | U+FE00-FE0F, U+E0100-E01EF, U+180B-180D, U+180F | CRITICAL/HIGH | Invisible payload encoding |
| Bidi controls (Trojan Source) | U+202A-202E, U+2066-2069, U+2028-2029, U+200E-200F, U+061C | CRITICAL/HIGH | Code displays differently than it executes |
| Tag characters | U+E0001, U+E0020-E007F | HIGH | Invisible ASCII mirror used in prompt injection |
| Reserved invisible code points | Rest of U+E0000-E0FFF, U+FFF0-FFF8, U+2065 | HIGH | Unassigned, but rendered as nothing, so usable as a hidden alphabet |
| Control characters | U+0000-001F except tab, LF and CR; U+007F-009F | INFO-HIGH | Escape sequences that rewrite terminal output; a NUL that makes review tools hide a diff |
| Zero-width characters | U+200B-200D, U+FEFF, U+2060 | MEDIUM | Steganographic encoding, string comparison bypass |
| Invisible identifiers | U+3164, U+FFA0, U+2800, U+115F-1160, U+13441-13442, U+16FE4 | MEDIUM | Invisible variable/function names |
| Invisible format/whitespace | U+00AD, U+2000-200A, U+2061-2064, U+3000, U+1BCA0-1BCA3, U+1D173-1D17A, ... | LOW-MEDIUM | String comparison bypass, obfuscation |

4,263 codepoints total: every code point Unicode marks as default-ignorable (drawn as nothing), every space and line separator other than the ordinary space, the control characters, and a few glyphs defined to be blank. Severity levels: CRITICAL > HIGH > MEDIUM > LOW > INFO.

Two groups of format characters are left out on purpose: the Egyptian hieroglyph format controls (U+13430-1343F) and the Arabic, Syriac and Kaithi number and abbreviation signs (U+0600-0605, U+06DD, U+070F, U+0890-0891, U+08E2, U+110BD, U+110CD). Unicode does not mark them as default-ignorable, which is the property that tells a renderer to draw nothing. They are not bidi controls, and no identifier can hold one.

Two things keep a single file from flooding the report. A NUL byte is reported once per file, and a file stops being scanned after 10,000 findings, with a warning. Form feed, which some source files use as a page break, is listed only at `--severity info`. A file that is really binary but has a source extension, or a fixture holding raw terminal escape sequences, will now be reported; add it to the allowlist.

## CLI Reference

```
heckler [paths...] [options]
heckler --vet PACKAGE [--registry npm|pypi]
```

| Flag | Description |
|---|---|
| `--ci` | Exit code 1 if findings detected, 2 if something could not be scanned |
| `--format text\|json\|sarif` | Output format (default: text) |
| `--severity LEVEL` | Minimum severity to report (default: low) |
| `--scan-deps` | Include dependency directories |
| `--diff-only` | With `--scan-deps`, only scan the packages changed in the lockfiles given as paths |
| `--allow-unscanned` | Do not fail (exit code 2) over what could not be scanned; it is still named in a warning. See the exit codes below |
| `--no-suppress` | Ignore `heckler-ignore` comments and report what they hide |
| `--vet PACKAGE` | Download and scan a package before installing (fetches directly from public registries) |
| `--registry npm\|pypi` | Package registry for `--vet` (auto-detected if omitted) |
| `--config PATH` | Path to `.heckler.yml` config file (error if not found) |
| `--no-color` | Disable colored output |
| `--quiet` | Only output findings, no summary |
| `--all-text` | Scan every text file inside dependency directories too, where a scan otherwise keeps to code |
| `--skip-binary` | Leave out a file passed by name when its content is not text, as a directory walk does |

Exit codes: `0` clean, `1` findings detected (with `--ci`), `2` error.

Scanning nothing is an error, not a clean result. A path that does not exist exits with 2, as do a missing `--config` file, a configuration file that cannot be used as it is written, and `--diff-only` given no lockfile. With `--ci`, so does anything heckler was asked to scan and could not: a file that is unreadable or larger than 50 MB, a named pipe, socket or device in a directory, a directory it cannot list, and, with `--diff-only`, a changed package that is not installed or is installed at another version, a lockfile heckler has no parser for, and a requirements line it cannot read. Each one is named in a warning on stderr. `--allow-unscanned` keeps the warnings and drops the exit code. `--vet` exits with 1 on findings and with 2 when part of the package could not be scanned, with or without `--ci`.

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

scanner.skipped     # [(path, reason), ...] for files that could not be scanned
scanner.suppressed  # {path: count} of findings hidden by heckler-ignore comments
scanner.skipped_dirs  # directories that were not entered because of their name
scanner.binary      # files that look binary, and were not scanned as text
```

## Configuration

Create `.heckler.yml` in your project root:

```yaml
severity: medium           # Minimum severity to report
allow_bom: true            # Do not report a U+FEFF that is the first character of a file
allow_emoji: true          # Report selectors and joiners inside emoji as INFO

allowlist:                 # Glob patterns for files to skip
  - "**/*.po"
  - "**/locale/**"

extra_skip_dirs:           # Additional directories to skip
  - third_party

extra_extensions:          # Extensions that are scanned whatever the file holds
  - .custom
```

Also reads `[tool.heckler]` from `pyproject.toml`, with the same keys.

`.heckler.yml` is a flat file. A setting is a `key: value` line, and a value is a word, a quoted string, a list in brackets on one line, or a list of `- item` lines. heckler reads the file with its own reader and nothing else, so it means the same thing wherever heckler runs. The rest of YAML (nested keys, anchors, block scalars) is an error, and so are a value that a setting cannot take (`severity: hgih`, `allow_bom: maybe`) and a `pyproject.toml` that is not valid TOML. The message names the line, and the exit code is 2: settings that were half read could switch off part of a scan.

Allowlist patterns are globs matched against the file path. `*` and `?` stay within one path segment, `**` spans any number of directories, a pattern without a leading `/` matches at any depth, and a trailing `/` covers everything under that directory. The allowlist also applies to files passed by name, which is how pre-commit runs heckler.

Emoji contain two of the characters heckler looks for: a presentation selector (U+FE0E or U+FE0F) after the character it styles, and a zero width joiner (U+200D) between two emoji. With `allow_emoji: true`, the default, those are reported at INFO, which is below the default threshold, so an emoji in a README or a string literal does not fail the scan. Use `--severity info` to list them. A selector anywhere else, or next to another variation selector, is still CRITICAL, so a run of them hidden behind an emoji is reported in full. The flags of England, Scotland and Wales are the only emoji built from tag characters (U+1F3F4, five tags, U+E007F); exactly those three sequences are reported at INFO, and every other run of tags stays HIGH. A line with more than 10 presentation selectors inside emoji is reported once, at LOW: each is harmless alone, but the choice of selector across a long row can carry data. Wrapping the row does not avoid that: a file in which more than 10 emoji are written in a presentation other than the one that emoji mostly has there (bare, U+FE0E or U+FE0F) is reported once, at LOW, and so is a file with more than 50 zero width joiners between emoji. Set `allow_emoji: false` to flag every occurrence.

Suppress the next line with a dedicated directive (preferred):

```javascript
// heckler-ignore-next-line U+FE0F
const emoji = "\uFE0F";

// heckler-ignore-next-line U+FE0F U+FE0E
const selectors = "\uFE0F\uFE0E";  // only the listed code points are suppressed

// heckler-ignore-next-line
const padded = "\u00A0";           // no list: MEDIUM and below only
```

Or suppress inline (legacy, still supported):

```javascript
const emoji = "\uFE0F"; // heckler-ignore U+FE0F
```

```python
emoji = "\uFE0F"  # heckler-ignore U+FE0F
```

A directive that lists code points suppresses exactly those. A directive without a list suppresses findings of MEDIUM severity and below. Bidi controls, variation selectors and tag characters are all HIGH or CRITICAL, so hiding one of them takes a directive that names it.

Supported comment tokens: `//`, `#`, `/*`, `--`, `;`, including runs such as `;;` and `///`. heckler finds directives by pattern; it does not parse the languages it scans. The pattern requires that:

- the directive ends its line, and `heckler-ignore-next-line` is alone on its line;
- the comment token starts the line or follows a space or tab, and `--` is followed by one;
- only spaces and tabs separate the parts.

So `heckler-ignore` in a variable name, in the middle of a string, at the end of a URL (`https://example.com/#heckler-ignore`) or as a flag (`--heckler-ignore`) does nothing. What the pattern cannot tell is whether a line that meets these rules is really a comment: a line of a multi-line string that ends in `# heckler-ignore` works as a directive. Three things limit what that can hide:

- a directive without a list never covers HIGH or CRITICAL characters;
- every run that suppressed something says so on stderr (unless `--quiet`), for example `Note: 3 finding(s) suppressed in 2 file(s) by heckler-ignore comments.`;
- `--no-suppress` ignores every directive and reports what they hide, which makes a good periodic CI audit.

Suppression directives are **never honored in dependency code** (node\_modules, vendor, site-packages, target) to prevent malicious packages from hiding attacks.

## What Gets Scanned

heckler scans text, whatever it is written in. A directory walk reads every file whose content is text, and a file passed by name is always scanned.

A file looks binary when more than one byte in 32 of its first 8 KB is a control byte. A NUL or two does not come to that, and a single byte never does, however short the file is. A file that looks binary is then read in full, because the start of a file is cheap to pad. It is left out as binary when more than a quarter of all its bytes are control bytes or invalid UTF-8, or when it is larger than 50 MB.

A file with less than that is mostly text, whatever its start looks like, and is scanned for the text inside it: every run of 32 or more characters that are valid UTF-8, and the whole file when all of it is. Control characters are not reported from that reading, `heckler-ignore` comments are not honoured in it, and its findings are marked `(in a file that looks binary)`. That reading has limits: text inside an image, an archive or an executable is not scanned, and neither are control characters or a stretch of fewer than 32 characters between bytes that are not UTF-8. So a run names every file that looks binary in a note on stderr, and so does `--vet` in its report, whether the file was left out or scanned for the text inside it. A binary format that is mostly text, a compiled translation catalog for one, is read like any other file that is, and can produce findings; add such files to the `allowlist` where the characters are expected.

A file whose name marks it as source, or whose first line starts with `#!`, is scanned whatever its bytes are, so nothing written into such a file takes it out of the scan; `extra_extensions` adds extensions to those names. `--skip-binary` applies the same rule to files passed by name, which is how the pre-commit hook runs.

Inside dependency directories a walk keeps to code: files that can be run or imported, the manifest that names a package's install scripts, and anything that starts with `#!`. `--all-text` scans every text file there too.

Some directories are not entered in a directory walk. Dependency and generated directories (`node_modules`, `vendor`, `site-packages`, `.venv`, `venv`, `.tox`, `.eggs`, `target`, `.next`, `.nuxt`, `coverage`) are scanned with `--scan-deps`, and a run that skipped one names it in a note on stderr. Version control data and tool caches (`.git`, `__pycache__`, `.mypy_cache`, `.ruff_cache`) are never scanned. `dist/` and `build/` are scanned like any other directory, because projects commit them; list them under `extra_skip_dirs` to leave them out.

Files encoded as UTF-16 or UTF-32 (with BOM) are detected and decoded. A file is read a second way when its bytes disagree with what it announces:

- A UTF-16 or UTF-32 BOM in front of content that is not in that encoding is reported at HIGH, and the file is scanned as UTF-8 as well. Otherwise two bytes in front of an ordinary file would be enough to hide everything in it. A stray NUL does not make UTF-8 text count as UTF-16.
- A file whose content does match its BOM is read as UTF-8 too, and code points from U+00A0 up are reported from that reading. Padding that makes the BOM believable therefore cannot hide UTF-8 text behind it.
- A file without a BOM that has a NUL in every other byte is also scanned as UTF-16, so the character is named and not only the NUL bytes around it. The same goes for UTF-16 in a script whose upper byte is a control character (Greek, Cyrillic, Hebrew, Arabic, Thai and others), and for UTF-32.

Findings from such a file say which reading they come from, for example `Right-to-Left Override (read as UTF-8)`. A line ends at LF, CRLF or a lone CR, so line numbers match what an editor shows.

### Dependency / Supply Chain Coverage

| Capability | Supported Ecosystems |
|---|---|
| `--vet` (pre-install scan) | npm, PyPI |
| `--diff-only` (lockfile parsing) | npm (lockfile v1 to v3), yarn (classic and berry), pnpm (lockfile v5 to v9), pip (`requirements*.txt`), pipenv, poetry |
| `--scan-deps` (installed deps) | node\_modules, vendor, site-packages and virtualenvs (`.venv`, `venv`, `.tox`, `.eggs`), target (Cargo) |

Lockfiles for Cargo, Go, Ruby, and Composer are detected but parsers are not yet implemented. Handed one of these, or a file it does not recognise, `--diff-only` warns and, with `--ci`, fails with exit code 2, because the packages behind it were not scanned. The same goes for a `package-lock.json` with a `lockfileVersion` newer than 3.

In a requirements file, an exact pin (`name==1.2.3`) is checked against the installed version. A bare name, a range (`>=`, `<`, `~=`, ...) or `name @ url` has no version to check, so whatever is installed under that name is scanned. A URL or a path is read for the package it names: an `#egg=` fragment gives the name (`-e git+https://host/repo.git#egg=name`), and the file name of a wheel or source archive gives the name and the version (`./wheels/name-1.0-py3-none-any.whl`). A directory inside the project, such as `-e .`, is the project's own code and is left to the source scan. A URL or path that names no package, and a line that cannot be read as a requirement, count as unscanned.

`--diff-only` scans the installed copy of each package that was added or bumped in the lockfile, so the dependencies have to be installed first. Node packages are looked up in `node_modules`, including pnpm's virtual store. Python packages are looked up in a virtualenv next to the lockfile or in the working directory (`.venv`, `venv`, `env`), then in the environment heckler runs in, then in the other interpreters on `PATH`, which is where an activated virtualenv is found when heckler runs under pre-commit. When the lockfile names a version, the installed copy has to be that version. A Python package is scanned through the list of files its installer recorded, and when an environment holds more than one record under the package's name, the files of each are scanned. With `--ci`, a changed package that is missing, installed at another version, or installed with no record that leads to its files fails the run with exit code 2 and is named in the output; `--allow-unscanned` turns that back into a warning.

`--vet` scans everything the registry offers for the version: the one tarball of an npm package, and for PyPI the sdist and every wheel, since which of them `pip` installs depends on the platform and nothing makes their contents agree. Inside each archive every text file is scanned, whatever it is called, which covers scripts without an extension and files that an interpreter runs at startup. The `[VET]` header names the files that were scanned, and a file that could not be unpacked or read makes the result `INCOMPLETE` (exit code 2) rather than `CLEAN`.

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

`@v1` follows the newest 1.x.y release; use a full version such as `@v1.1.0` to pin one. Versions follow [Semantic Versioning](https://semver.org/).

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
    rev: v1.1.0
    hooks:
      - id: heckler          # Scan source files
      - id: heckler-lockfile         # Scan changed dependencies on lockfile change
```

The source hook is handed every staged file and leaves out those whose content is not text.

The lockfile hook scans installed packages, so install dependencies before committing a lockfile change. If a changed package is not installed, the hook fails and names it; add `args: [--allow-unscanned]` to the hook to accept that instead.

### Dependency Scanning Workflow

[`examples/dependency-scan.yml`](examples/dependency-scan.yml) is a workflow to copy into `.github/workflows/` of your own repository. It runs when a lockfile in the repository root changes, once a week, and on demand. It installs the dependencies into the workspace (`node_modules` for npm, yarn and pnpm; `.venv` for uv, poetry, pipenv and `requirements*.txt`), scans those directories with `--scan-deps`, and writes the findings to the job summary.

- A package does not get to run code before it is scanned: install scripts are off and Python packages come from wheels only. One case is left. pip, pipenv and poetry build a requirement that points at a URL, a path or a git repository whatever they are told, which is why the job has a read-only token.
- Nothing is cached. The weekly run scans again with the current heckler release and with whatever an unpinned requirement resolves to that week.
- A run with nothing to scan fails: no lockfile it can install from, or an install that left no packages in the workspace, as Yarn Plug'n'Play does.

## Defense-in-Depth

| Layer | When | Speed | What it catches |
|---|---|---|---|
| `--vet` | Before `npm add` / `pip install` | ~5s | Malicious packages before they enter your project |
| Pre-commit (source) | `git commit` | <2s | Invisible chars in your own code |
| Pre-commit (lockfile) | Lockfile change + commit | <2s | Changed deps via diff-based scanning |
| CI source scan | PR / push | <5s | Source scan, enforceable |
| CI dep scan | Lockfile change + weekly | The install, then 30-60s | Installed dependencies |

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
- **Hardening** — tests for bypass resistance including null-byte injection, heckler-ignore abuse, U+2028/2029 detection, UTF-16/32 encoding evasion, missing config errors, and file selection
- **Reference data** — holds the character table and the emoji ranges to the Unicode property data in `regex`, and version and requirement parsing to `packaging`. Both are installed for the tests only

## License

MIT
