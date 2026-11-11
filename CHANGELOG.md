# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Detection of every default-ignorable code point, including the unassigned ones in U+E0000-E0FFF and U+FFF0-FFF8, which render as nothing
- Detection of control characters other than tab, LF and CR, as a new `control_character` category
- Detection of U+180F, U+1BCA0-1BCA3, U+1D173-1D17A and the blank glyphs U+13441-13442, U+16FE4 and U+1D159
- `--diff-only` parses pnpm lockfile v9 and `Pipfile.lock`
- `--diff-only` finds Python packages in the project's virtualenv, or through `PATH`, when heckler runs in its own environment under pre-commit, and resolves them by distribution name rather than import name
- `--diff-only` uses the commit range pre-commit is checking when nothing is staged
- `--allow-unscanned`
- The text report shows each offending line with its invisible characters spelled out

### Changed

- A file with a source extension that contains NUL or other control bytes is reported instead of being treated as binary
- A NUL byte is reported once per file, and scanning a file stops after 10,000 findings
- `scripts/heckler-scan.sh` looks for the same characters as the Python scanner; it previously missed 27 of them
- `--diff-only --ci` exits with code 2 when a changed package is not installed, or is installed at a different version than the lockfile names, instead of passing with a warning
- The `heckler-lockfile` pre-commit hook only triggers on lockfiles heckler can parse
- Variation selectors and zero width joiners inside well-formed emoji are reported at INFO instead of CRITICAL and MEDIUM; set `allow_emoji: false` to flag every occurrence as before
- `--all-text` leaves out files that have an unrecognised name and NUL bytes in their first 8 KB

### Fixed

- The allowlist applies to files passed by name, which is how the pre-commit hook receives them
- `**` in allowlist patterns matches any number of directories on every supported Python version
- `--diff-only` detects version bumps of existing packages in `package-lock.json`, `yarn.lock` and `poetry.lock`, not only newly added packages
- Dependency constraints in `poetry.lock` are no longer read as package names
- Inline `# comments` in `.heckler.yml` are no longer read as part of the value when PyYAML is not installed
- `scripts/heckler-scan.sh` no longer reports a clean result when it could not check: it skipped any file containing a NUL byte, and in a non-UTF-8 locale `grep` rejected the pattern and the error was discarded
- `scripts/heckler-scan.sh` spells out control characters in its listing instead of printing them raw, and no longer dies with a broken pipe on long listings

### Security

- A NUL byte no longer hides the rest of a file from the scanner

## [1.0.0] - 2026-03-23

Initial stable release and GitHub Actions Marketplace launch.

### Added

- Detect dangerous invisible Unicode characters (Glassworm, Trojan Source, zero-width, tag characters)
- GitHub Actions Marketplace release (`uses: kholcomb/heckler@v1`)
- GitHub Release creation and floating major version tag in release workflow
- Detect UTF-16/32 encoded files to prevent encoding evasion
- Prefer wheel downloads in `--vet` to avoid setup.py code execution
- Scan well-known extensionless files (Dockerfile, Makefile, etc.) by default
- Support for 60+ language file extensions
- Multi-ecosystem dependency scanning (npm, pip, Cargo, Go, Ruby, etc.)
- Output formats: text, JSON, SARIF (with GitHub Security tab upload)
- Pre-commit hook integration
- Integration tests and hardening test suite

### Security

- Harden scanner against threat-model bypass techniques
- Harden suppression directives against bypass attacks
- Harden archive extraction against path traversal
- Replace npm/pip subprocess calls with direct registry API fetches

[1.0.0]: https://github.com/kholcomb/heckler/releases/tag/v1.0.0
