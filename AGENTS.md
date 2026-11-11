# AGENTS.md

Guidance for coding agents working in this repository. Each section stands on its own; read the ones the task touches.

## What this is

heckler detects dangerous invisible Unicode (Glassworm variation selectors, Trojan Source bidi controls, zero-width and tag characters, control characters) in source code and in installed dependencies. The same code ships four ways from this repository: the `heckler` CLI and library on PyPI, a composite GitHub Action (`action.yml`), pre-commit hooks (`.pre-commit-hooks.yaml`), and a grep-only fallback (`scripts/heckler-scan.sh`).

It is a zero-dependency package: standard library only, Python 3.9+. PyYAML and `tomli` are used when present and never required, which is why `config.py` carries its own small YAML and TOML readers.

`README.md` documents the tool for its users (options, exit codes, configuration, what is detected). `CONTRIBUTING.md` covers setup, style and the release process. `CHANGELOG.md` records what changed and why.

## Commands

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install                      # lint/format on commit, Conventional Commits on the message

pytest                                  # whole suite, a few seconds
pytest tests/test_scanner.py::TestScanPath::test_skip_dirs   # one test
pytest -k bom                           # by keyword
pytest --cov=heckler --cov-report=term-missing               # what CI runs

ruff check src/ tests/
ruff format --check src/ tests/         # drop --check to rewrite
mypy src/                               # strict
python -m heckler --ci --severity low . # self-scan: the tree must hold none of the characters
python scripts/sync_shell_includes.py   # after changing the scanner's file lists (--check to verify)
```

CI (`.github/workflows/ci.yml`) runs lint, format, tests and the self-scan on Python 3.9 to 3.13, and mypy once. Run the self-scan as `python -m heckler` from the development environment, so that it is the working tree that runs.

## Architecture

Everything is in `src/heckler/`.

- `characters.py` is the data: the table of flagged code points with their severity and category, the compiled `DANGEROUS_UNICODE_RE`, and the rules for what counts as part of a well-formed emoji (reported at INFO instead of at full severity).
- `scanner.py` is the engine, in three layers that are worth keeping apart:
  1. **Which files** a directory walk scans: extension and file-name lists, the skipped directory names, a shorter list inside dependency directories, and a content check that replaces the lists under `--all-text`. A file passed by name is always scanned.
  2. **How bytes become text**: a file is read in the encoding it announces and, when the bytes disagree with that, in a second one as well, with each finding labelled by the reading it came from.
  3. **`scan_text`**, the core primitive: the regex, emoji handling, and `heckler-ignore` / `heckler-ignore-next-line` directives.

  The `Scanner` also records what it did not scan or did not report (`skipped`, `suppressed`, and similar lists). It prints nothing about them itself; the callers turn them into warnings and exit codes.
- `cli.py` has three modes that share one ending, `_finish()`, which prints the report and picks the exit code: the plain scan, `--vet` (`vet.py`), and `--scan-deps --diff-only` (`lockfile.py`). Exit codes: 0 clean, 1 findings (with `--ci`), 2 something could not be scanned or the tool failed.
- `lockfile.py` reads `git diff` of a lockfile, works out which packages were added or bumped (one parser per ecosystem), finds the installed copy of each in `node_modules` or a site-packages directory, and scans it.
- `vet.py` downloads a package from the public npm or PyPI registry with the standard library alone, checks its checksum, unpacks it with path-traversal checks, and scans every text file in every archive. It never runs package code.
- `config.py` merges `.heckler.yml` and `[tool.heckler]` into a `Config`; `formatters/` renders text, JSON and SARIF.

## Rules the code is built around

Most review comments and most past fixes come back to these.

- **Scanning nothing is an error, not a clean result.** A missing path, an unreadable or oversized file, a changed package that is not installed, a lockfile with no parser: each is named in a warning and, with `--ci`, fails the run with exit code 2 unless `--allow-unscanned` is given. New code paths that can skip something need the same treatment.
- **The content of a file can add it to a scan and can never take it out.** A recognised name is scanned whatever the bytes are, and no single byte (a NUL, a byte order mark) decides how or whether a file is read. An attacker writes the content.
- **Suppression cannot be forged.** A directive has to be a real comment, a directive without a code point list covers MEDIUM and below only, and directives are never honoured in dependency code or under `--scan-deps`.
- **No runtime dependencies, and nothing newer than Python 3.9** in syntax or standard library use.

## Things that have to stay in step

Tests fail when these drift, so change both sides together.

- `README.md` and the code (`tests/test_readme.py`): the extension table lists exactly `DEFAULT_TEXT_EXTENSIONS`, the "N+ file extensions" figure and the code point count are checked, every CLI option appears in the CLI Reference, and the example output is what the tool really prints.
- `scripts/heckler-scan.sh` and the scanner's file lists (`tests/test_coverage.py`): the list in the script is generated, so run `scripts/sync_shell_includes.py` and do not edit it by hand.
- The `files:` pattern of the `heckler-lockfile` hook in `.pre-commit-hooks.yaml` and `detect_ecosystem()` in `lockfile.py` (`tests/test_lockfile.py`).
- `CHANGELOG.md` follows Keep a Changelog. User-visible changes go under `[Unreleased]` as one-line entries that describe behaviour.

## Tests and fixtures

- Fixtures are inert. A sample is flagged characters sitting in a comment or a string, read back by nothing: no decoders, no working attack samples, no fixture that executes.
- Tests do not touch the network, and nothing is downloaded to verify a change. The vet tests replace `download_package` with archives built in `tmp_path`; the lockfile tests stage a real lockfile in this repository and clean up after themselves.
- No file in the repository may hold a literal invisible character, since the self-scan runs in CI. Build them with `chr(0x200B)` and the like. An escape sequence can reach the disk as the literal character depending on how the file was written, so after creating or editing a file that is meant to hold one, run the self-scan and `grep -nP '[^\x00-\x7F]'` on it.
- Hand-aligned data tables are wrapped in `# fmt: off` / `# fmt: on`; leave the formatter out of them.

## Commits and releases

- Commit subjects follow Conventional Commits (`fix(scanner): ...`); the commit-msg hook rejects anything else. `main` takes changes through pull requests only.
- Versions follow Semantic Versioning, and `CONTRIBUTING.md` says what counts as MAJOR, MINOR and PATCH for this tool. The version lives in `src/heckler/_version.py`.
- A release is a tag of the form `vMAJOR.MINOR.PATCH` on `main`. `.github/workflows/release.yml` runs for no other tag, and stops before publishing when the tag does not match `_version.py` or `CHANGELOG.md` has no section for the version. It publishes to PyPI, creates the GitHub release, and moves the major tag (`v1`) to the newest release of that major version.
