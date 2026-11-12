# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Scanner.scan_path(path, by_content=True)` treats a file passed by name as a directory walk does, and leaves it out when its content is binary

### Changed

- A file with an unrecognised name whose first 8 KB look binary is read in full before it is left out. When no more than a quarter of its bytes are control bytes or invalid UTF-8 it is mostly text, and is scanned for the text inside it: every run of 32 or more characters that are valid UTF-8, without control characters and without `heckler-ignore` comments, with its findings marked `(in a file that looks binary)`. A file with more than that is left out as binary, as before
- A binary format that is mostly text, such as a compiled translation catalog, is read by that rule and can produce findings. Add such files to the `allowlist` where the characters are expected
- The note on stderr names the files that look binary, up to five of them, instead of counting them, and calls them `not scanned as text`, as `--vet` does in its report. A file that is mostly text is named there as well as scanned, because control characters and stretches of fewer than 32 characters between bytes that are not UTF-8 are not reported from it
- `--diff-only --all-text` no longer drops a file that a changed Python package installed, without a word, because it looks binary. The file is read by the same rule, and named in the note when it is left out

### Fixed

- A named pipe in a directory no longer hangs the scan. It is named in a warning, as a socket or a device is, and counts as not scanned (exit code 2 with `--ci`)

### Security

- Control bytes at the top of a text file with an unrecognised name no longer take the file out of a directory walk, of `--vet`, of the `heckler` pre-commit hook or of `--diff-only --all-text`. 260 of them in a comment were enough, and the run reported nothing. It now takes control bytes or invalid UTF-8 that come to more than a quarter of the file, and the file is named
- A single control byte no longer makes a file shorter than 32 bytes binary
- `--vet` applies its limits on unpacked size, 50 MB for a file and 500 MB for an archive, to tar archives on every Python version. They were checked on Python 3.11.0 to 3.11.3 only, so a tarball of a few KB could unpack to any size. A member that declares a negative size is refused. So is what those limits do not reach: a sparse member, before its map is read, and the long-name or pax headers in front of one member when they come to more than 1 MB, or to more than 16 headers
- A file or directory name printed in a note or a warning has its control and invisible characters spelled out as `<U+XXXX>`, so a name cannot send an escape sequence or a line break to the terminal

## [1.1.0] - 2026-11-11

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
- Inside dependency directories more kinds of code are scanned, and the manifest that names a package's install scripts
- A file that starts with `#!` is scanned in a directory walk whatever it is called, inside dependencies too
- A scan says what it left out: a note on stderr names the directories it skipped by name and counts the files it took for binary. `--vet` names those files in its report
- `--skip-binary` leaves out a file passed by name when its content is not text, as a directory walk does
- `ConfigError`, which `load_config()` and `scan()` raise for a configuration file that cannot be used as it is written
- `Scanner.skipped`, `Scanner.suppressed`, `Scanner.skipped_dirs` and `Scanner.binary` tell library users what was not scanned and what was suppressed

### Changed

- Python 3.11 or newer is required
- A directory walk scans every file whose content is text, whatever it is called. It used to scan only the names on a built-in list, and to pass over the rest without a word
- `.heckler.yml` is read by heckler's own reader everywhere, also where PyYAML is installed, so that a file means one thing. The rest of YAML (nested keys, anchors, block scalars) is an error with exit code 2
- A setting with a value it cannot take is an error with exit code 2 instead of being ignored or guessed at: an unknown `severity`, an `allow_bom` or `allow_emoji` that is not true or false, a list setting that is not a list of strings. `on` and `off` are read as true and false
- The `heckler` pre-commit hook is handed every staged file and leaves out the binary ones itself
- A presentation selector or a joiner counts as part of an emoji only next to a code point that Unicode lists as an emoji or keeps free for one. Next to any other symbol it is reported at full severity
- A file with a source extension that contains NUL or other control bytes is reported instead of being treated as binary
- A NUL byte is reported once per file, and scanning a file stops after 10,000 findings
- `--diff-only --ci` exits with code 2 when a changed package is not installed, or is installed at a different version than the lockfile names, instead of passing with a warning
- The `heckler-lockfile` pre-commit hook only triggers on lockfiles heckler can parse
- Variation selectors and zero width joiners inside well-formed emoji are reported at INFO instead of CRITICAL and MEDIUM; set `allow_emoji: false` to flag every occurrence as before
- A file with an unrecognised name is left out as binary when more than one byte in 32 of its first 8 KB is a control byte, and never one that starts with `#!`. A file with a NUL or two in it is scanned, and the NUL reported
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
- `--all-text` is about dependencies only, where a scan otherwise keeps to code: it scans every text file in dependency directories and in a package changed in a lockfile
- `--vet` reports file paths with the archive they are in (`pkg-1.0.tar.gz/pkg-1.0/setup.py`), and exits with code 2 when part of a package could not be scanned
- The flags of England, Scotland and Wales, the only emoji built from tag characters, are reported at INFO instead of HIGH
- Files are reported in sorted order, the same on every filesystem
- The dependency scan workflow is now an example to copy, `examples/dependency-scan.yml`, and no longer runs in this repository, which has no dependencies to scan. It installs heckler from PyPI, scans only the directories it installed into, starts only for the lockfiles it can install from (uv is new; Go, Ruby and Composer lockfiles no longer start it), and keeps no cache, so the weekly run scans again
- A release is a tag of the form `vMAJOR.MINOR.PATCH` and nothing else. The release workflow stops before publishing when the tag does not match the package version or this file has no section for it, and a major tag such as `v1` moves only to the newest release of its major version

### Removed

- `scripts/heckler-scan.sh`, the grep fallback for machines without Python. It could not do what the scanner does (no severities, no second reading of a file whose encoding is in doubt, no emoji rules, no allowlist or suppression comments), and a clean result from it said less than it appeared to. There is one scanner to maintain now

### Fixed

- The allowlist applies to files passed by name, which is how the pre-commit hook receives them
- `**` in allowlist patterns matches any number of directories on every supported Python version
- `--diff-only` detects version bumps of existing packages in `package-lock.json`, `yarn.lock` and `poetry.lock`, not only newly added packages
- Dependency constraints in `poetry.lock` are no longer read as package names
- Inline `# comments` in `.heckler.yml` are no longer read as part of the value
- A list in brackets in `.heckler.yml` is no longer split at a comma inside a quoted string
- A `pyproject.toml` that is not valid TOML is an error with exit code 2 instead of a traceback
- `--diff-only` compares versions as PEP 440 does, so `1.0a1` and `1.0alpha1`, or `1.0.post1` and `1.0-1`, are one version and no longer reported as installed at the wrong one
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
- A single NUL byte no longer opts a file out of a directory walk or of `--vet`
- A NUL byte in the first 1,024 bytes of a file no longer keeps it from the `heckler` pre-commit hook, which used to receive only what pre-commit classified as text
- `allow_bom: off` in `.heckler.yml` is read as false. Where PyYAML was not installed it was taken for a non-empty string, which is true
- Text that is shaped like a suppression directive but is not a comment, such as a `#heckler-ignore` URL fragment or a `--heckler-ignore` flag at the end of a line, no longer suppresses findings
- `--vet` no longer passes a PyPI release on the strength of its wheel alone when the sdist, or another wheel, holds the characters
- `--diff-only` asks the interpreters on `PATH` where their packages are without importing anything from the working directory. A `sysconfig.py` in the repository being checked was imported, and so run, by each of them
- `--diff-only` no longer passes a changed Python package on the strength of the first installed metadata entry that carries its name, which a package can ship among its own files. Every entry under the name is scanned, an entry also counts by the name and version in its metadata file, and a package whose metadata leads to none of its installed files counts as unscanned (exit code 2 with `--ci`)

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

[1.1.0]: https://github.com/kholcomb/heckler/releases/tag/v1.1.0
[1.0.0]: https://github.com/kholcomb/heckler/releases/tag/v1.0.0
