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
- `--no-suppress` ignores `heckler-ignore` comments and reports what they hide; every run that suppressed something prints how many findings, in how many files
- `--diff-only` reads `package-lock.json` files with `lockfileVersion` 1, and treats `requirements*.txt` (`requirements-dev.txt`, ...) as pip requirements; the `heckler-lockfile` pre-commit hook triggers on them
- `--diff-only` scans packages from requirement lines without an exact pin: a bare name, `>`, `<` and `name @ url`
- `--diff-only` scans packages from requirement lines given as a URL or a path. The name comes from an `#egg=` fragment (`-e git+https://host/repo.git#egg=name`) or from the file name of a wheel or source archive, which gives the version too (`./wheels/name-1.0-py3-none-any.whl`). A directory inside the project (`-e .`) is left to the source scan, and a URL or path that names no package counts as unscanned
- `--vet` scans the sdist and every wheel of a PyPI release instead of one of them, scans every text file in each archive whatever its extension, and names the scanned files in the `[VET]` header
- A UTF-16 or UTF-32 byte order mark on content that is not in that encoding is reported at HIGH, and the file is scanned as UTF-8 as well
- A file with a UTF-16 or UTF-32 byte order mark is read as UTF-8 as well even when its content matches the mark, and U+00A0 and above is reported from that reading
- A file without a byte order mark that has a NUL in every other byte is also scanned as UTF-16, so the characters in it are named
- UTF-32 without a byte order mark, and UTF-16 without one in Greek, Cyrillic, Hebrew, Arabic, Thai and the other scripts whose upper byte is a control character, are also read in that encoding, so the character is named
- More than 10 presentation selectors inside emoji on one line are reported once, at LOW
- A file that writes more than 10 emoji in a presentation other than the one that emoji mostly has there (bare, U+FE0E or U+FE0F), or that holds more than 50 zero width joiners between emoji, is reported once, at LOW, however its lines are wrapped
- Scanned by default: `.cc`, `.hh`, `.htm`, `.ipynb`, `.erb`, `.mdc`, `.mts`, `.cts`, `.pth`, `Jenkinsfile`, `.env`, `.env.*`, `Dockerfile.*`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `.cxx`, `.hxx`, `.jsonc`, `.json5`, `.sass`, `.less`, `.kts`, `.rst`, `.adoc`, `.j2`, `.jinja2`, `.pyx`, `.pxd`, `.pxi`, `Containerfile`, `Containerfile.*`, `go.mod`, `go.sum` and `go.work`
- Scanned inside dependencies: `.mts`, `.cts`, `.vue`, `.svelte`, `.pth`, `.ps1`, `.bat`, `.cc`, `.hh`, `.pyx`, `.pxd`, `.pxi` and `package.json`
- A file that starts with `#!` is scanned in a directory walk whatever it is called, inside dependencies too
- A scan says what it left out: a note on stderr names the directories it skipped by name and, with `--all-text`, counts the files it took for binary. `--vet` names those files in its report
- `[tool.heckler]` in `pyproject.toml` is read on Python 3.9 and 3.10 without `tomli` installed; a line that cannot be read there is named in a warning
- `Scanner.skipped`, `Scanner.suppressed`, `Scanner.skipped_dirs` and `Scanner.binary` tell library users what was not scanned and what was suppressed
- `scripts/sync_shell_includes.py` writes the file list of `scripts/heckler-scan.sh` from the scanner's lists

### Changed

- A file with a source extension that contains NUL or other control bytes is reported instead of being treated as binary
- A NUL byte is reported once per file, and scanning a file stops after 10,000 findings
- `scripts/heckler-scan.sh` looks for the same characters as the Python scanner; it previously missed 27 of them
- `--diff-only --ci` exits with code 2 when a changed package is not installed, or is installed at a different version than the lockfile names, instead of passing with a warning
- The `heckler-lockfile` pre-commit hook only triggers on lockfiles heckler can parse
- Variation selectors and zero width joiners inside well-formed emoji are reported at INFO instead of CRITICAL and MEDIUM; set `allow_emoji: false` to flag every occurrence as before
- `--all-text` leaves out a file with an unrecognised name when more than one byte in 32 of its first 8 KB is a control byte, and never one that starts with `#!`. A file with a NUL or two in it is scanned, and the NUL reported
- `dist/` and `build/` are scanned by default, because projects commit them. List them under `extra_skip_dirs` to leave them out
- `--scan-deps` also scans `.tox`, `.eggs`, `.next`, `.nuxt` and `coverage`
- `--diff-only` without a lockfile to check is an error (exit code 2) instead of a clean result
- A path that does not exist is an error (exit code 2) instead of a clean result
- With `--ci`, a file that could not be scanned because it is unreadable or larger than 50 MB, and a directory that could not be listed, fail the run with exit code 2 and are named in a warning. `--allow-unscanned` now covers these too
- `--diff-only --ci` exits with code 2 for a lockfile heckler cannot read (an unknown file, Cargo, Go, Ruby, Composer, a `package-lock.json` newer than version 3) and for a requirements line it cannot read, instead of passing with a warning
- A `heckler-ignore` or `heckler-ignore-next-line` comment without a list of code points suppresses MEDIUM and below only. HIGH and CRITICAL characters (bidi controls, variation selectors, tag characters) need to be listed, as in `heckler-ignore U+FE0F`
- The comment token of a directive has to start the line or follow a space or tab, `--` has to be followed by one, and only spaces and tabs may separate the parts of a directive
- The line that holds a `heckler-ignore-next-line` directive is itself scanned
- A lone CR ends a line, so line numbers in files with CR-only line endings match an editor's, and a directive covers one line of such a file rather than all of it
- `--all-text` applies inside dependency directories and to the files of a package changed in a lockfile
- `--vet` reports file paths with the archive they are in (`pkg-1.0.tar.gz/pkg-1.0/setup.py`), and exits with code 2 when part of a package could not be scanned
- The flags of England, Scotland and Wales, the only emoji built from tag characters, are reported at INFO instead of HIGH
- Files are reported in sorted order, the same on every filesystem
- The file list of `scripts/heckler-scan.sh` is the scanner's default list; it used to cover 30 extensions and no extensionless files
- The dependency scan workflow is now an example to copy, `examples/dependency-scan.yml`, and no longer runs in this repository, which has no dependencies to scan. It installs heckler from PyPI, scans only the directories it installed into, starts only for the lockfiles it can install from (uv is new; Go, Ruby and Composer lockfiles no longer start it), and keeps no cache, so the weekly run scans again
- A release is a tag of the form `vMAJOR.MINOR.PATCH` and nothing else. The release workflow stops before publishing when the tag does not match the package version or this file has no section for it, and a major tag such as `v1` moves only to the newest release of its major version

### Fixed

- The allowlist applies to files passed by name, which is how the pre-commit hook receives them
- `**` in allowlist patterns matches any number of directories on every supported Python version
- `--diff-only` detects version bumps of existing packages in `package-lock.json`, `yarn.lock` and `poetry.lock`, not only newly added packages
- Dependency constraints in `poetry.lock` are no longer read as package names
- Inline `# comments` in `.heckler.yml` are no longer read as part of the value when PyYAML is not installed
- `scripts/heckler-scan.sh` no longer reports a clean result when it could not check: it skipped any file containing a NUL byte, and in a non-UTF-8 locale `grep` rejected the pattern and the error was discarded
- `scripts/heckler-scan.sh` spells out control characters in its listing instead of printing them raw, and no longer dies with a broken pipe on long listings
- `.env.example` was in the extension list, where it could never match; `.env` and `.env.*` are now matched by name
- A requirement pinned with a wildcard (`name==1.*`) is no longer reported as installed at the wrong version
- The example in the README is the tool's real output, and a test keeps it so
- A finding in a package that pnpm installed, or in a nested `node_modules`, names that package. It used to name `.pnpm` or the outer package
- `--vet` names an archive it could not unpack as not scanned in its `[VET]` report (`INCOMPLETE`) and goes on to scan the package's other files. It used to stop with an error message
- The dependency scan workflow scans Python dependencies. It installs them into `.venv` in the workspace; they used to be installed outside it, where `--scan-deps .` never looked
- The dependency scan workflow no longer reports a clean result when it found no lockfile to install from, when the install left nothing to scan, or when the scan's output could not be read

### Security

- A NUL byte no longer hides the rest of a file from the scanner
- The dependency scan workflow installs without running install scripts and takes Python packages from wheels only, with a read-only token that is not left in the checkout
- A UTF-16 byte order mark in front of UTF-8 text no longer hides the text from the scanner
- A NUL byte after a UTF-16 byte order mark no longer makes heckler take UTF-8 text for UTF-16, which hid the text, and neither does UTF-16 padding in front of it
- A single NUL byte no longer opts a file out of `--all-text` and `--vet`
- Text that is shaped like a suppression directive but is not a comment, such as a `#heckler-ignore` URL fragment or a `--heckler-ignore` flag at the end of a line, no longer suppresses findings
- `--vet` no longer passes a PyPI release on the strength of its wheel alone when the sdist, or another wheel, holds the characters

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
