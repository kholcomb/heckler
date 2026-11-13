# AGENTS.md

Guidance for coding agents working in this repository. Each section stands on its own; read the ones the task touches.

## What this is

heckler detects dangerous invisible Unicode (Glassworm variation selectors, Trojan Source bidi controls, zero-width and tag characters, control characters) in source code and in installed dependencies. The same code ships three ways from this repository: the `heckler` CLI and library on PyPI, a composite GitHub Action (`action.yml`), and pre-commit hooks (`.pre-commit-hooks.yaml`).

It is a zero-dependency package: standard library only, Python 3.11+. `config.py` reads `.heckler.yml` with its own small reader and never with a YAML library, so the file means the same thing in every environment. `regex` and `packaging` are in the dev extra as reference implementations for the tests to check the code against; nothing in `src/` imports them.

`README.md` documents the tool for its users (options, exit codes, configuration, what is detected). `CONTRIBUTING.md` covers setup, style and the release process. `CHANGELOG.md` records what changed and why.

## Commands

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install                      # lint, format and type checks on commit, Conventional Commits on the message

pytest                                  # whole suite, a few seconds
pytest tests/test_scanner.py::TestScanPath::test_skip_dirs   # one test
pytest -k bom                           # by keyword
pytest --cov=heckler --cov-report=term-missing               # what CI runs

ruff check src/ tests/
ruff format --check src/ tests/         # drop --check to rewrite
mypy src/                               # strict
pyright                                 # strict, src/ only ([tool.pyright] in pyproject.toml)
zizmor --offline .                      # after a change to a workflow or to action.yml
python -m heckler --ci --severity low . # self-scan: the tree must hold none of the characters
```

CI (`.github/workflows/ci.yml`) runs lint, format, tests and the self-scan on Python 3.11 to 3.14 on Linux and on 3.12 on Windows and macOS, and mypy and Pyright once. It also runs the hooks in `.pre-commit-config.yaml`, and then the shipped `heckler` hook and the action in `action.yml`: each on the tree, which has to pass, and on a file with a character planted at run time, which has to fail. The action's scan of the tree is uploaded to code scanning, which the ruleset on `main` requires; that job alone has `security-events: write`. It builds the package and installs the wheel with no index, so that a runtime dependency fails there, and it lints the workflows with actionlint and zizmor. Run the self-scan as `python -m heckler` from the development environment, so that it is the working tree that runs.

## Architecture

Everything is in `src/heckler/`.

- `characters.py` is the data: the table of flagged code points with their severity and category, the compiled `DANGEROUS_UNICODE_RE`, and the rules for what counts as part of a well-formed emoji (reported at INFO instead of at full severity). The tables are static, so a result does not depend on the Unicode version of the interpreter that runs the scan.
- `scanner.py` is the engine, in three layers that are worth keeping apart:
  1. **Which files** a directory walk scans: every file whose content is text. The extension and file-name lists are a floor under that check, not a filter: a listed name is scanned whatever its bytes are. Some directory names are skipped, and inside dependency directories the walk keeps to code unless `--all-text` is given. A file passed by name is always scanned, unless `--skip-binary` asks for the walk's rule.
  2. **How bytes become text**: a file is read in the encoding it announces and, when the bytes disagree with that, in a second one as well, and a file whose first or second line declares a source encoding is read in that one too, with each finding labelled by the reading it came from. A file whose start looks binary but which is mostly text is read for its runs of valid UTF-8, without control characters and without directives, and is recorded in `binary` like every file that looks binary.
  3. **`scan_text`**, the core primitive: the regex, emoji handling, and `heckler-ignore` / `heckler-ignore-next-line` directives.

  The `Scanner` also records what it did not scan or did not report (`skipped`, `suppressed`, and similar lists). It prints nothing about them itself; the callers turn them into warnings and exit codes.
- `cli.py` has three modes that share one ending, `_finish()`, which prints the report and picks the exit code: the plain scan, `--vet` (`vet.py`), and `--scan-deps --diff-only` (`lockfile.py`). Exit codes: 0 clean, 1 findings (with `--ci`), 2 something could not be scanned or the tool failed.
- `lockfile.py` reads `git diff` of a lockfile, works out which packages were added or bumped (one parser per ecosystem), finds the installed copy of each in `node_modules` or a site-packages directory, and scans it.
- `vet.py` downloads a package from the public npm or PyPI registry with the standard library alone, checks its checksum, unpacks it with path-traversal and size checks, and scans every text file in every archive. It never runs package code.
- `_output.py` is the only writer to standard output and standard error for everything heckler says itself. `write_err()` and `write_line()` print a message with every control and invisible character spelled out as `<U+XXXX>` (`spell_out()` in `formatters/text.py`), so a name in it cannot send an escape sequence or a line break to the terminal; the argument parser's errors go out through `write_err()` too (`_Parser.error()` in `cli.py`), and only argparse's own `--help` and `--version` text, which holds no input, goes out through argparse. `write_out()` prints a formatter's document as it is; what a formatter does with a name is that formatter's concern. It escapes what the stream cannot encode, probing with the stream's own error handler, so that a report is never lost to a `UnicodeEncodeError`. A test fails on a `print()` call, or a `sys.stdout.write()` or `sys.stderr.write()` call, inside a function anywhere else in the package, and on a call to `write_out()` that is not given a formatter's output.
- `config.py` merges `.heckler.yml` and `[tool.heckler]` into a `Config`, and raises `ConfigError` for what it cannot read or use; `formatters/` renders text, JSON and SARIF.

## Rules the code is built around

Most review comments and most past fixes come back to these.

- **Scanning nothing is an error, not a clean result.** A missing path, an unreadable or oversized file, a changed package that is not installed, a lockfile with no parser: each is named in a warning and, with `--ci`, fails the run with exit code 2 unless `--allow-unscanned` is given. New code paths that can skip something need the same treatment.
- **Only being binary leaves a file out of a walk, and never a file whose name marks it as source.** A recognised name is scanned whatever the bytes are, no single byte (a NUL, a byte order mark) decides how or whether a file is read, and a file that looks binary is named in the report. Binary is settled over the whole file: one whose start looks binary is read in full, and is left out only when more than a quarter of it is control bytes or invalid UTF-8. With less, it is scanned for the text inside it and named all the same, because that reading leaves out control characters and short stretches. An attacker writes the content.
- **Settings are read in full or not at all.** A configuration file that cannot be used as it is written is an error with exit code 2, never a quiet fall back to the defaults, which could switch a check off.
- **Suppression cannot be forged.** A directive has to be a real comment, a directive without a code point list covers MEDIUM and below only, and directives are never honoured in dependency code, under `--scan-deps` or in a file that looks binary, and in a declared reading only on a line that reads the same in UTF-8.
- **A name is written by whoever made it.** A path, an archive member, a package name or version, a lockfile path: any of them can hold an escape sequence or a line break. A message goes out through `write_err()` or `write_line()`, which spell out every control and invisible character (a tab is printed as a space), and the text formatter spells out each name it prints. Besides those, a formatter's document goes out through `write_out()` as the formatter made it, and argparse prints its own `--help` and `--version` text, which holds no input.
- **No runtime dependencies, and nothing newer than Python 3.11** in syntax or standard library use. A library may check the code from the tests; the code may not import it.

## Things that have to stay in step

Tests fail when these drift, so change both sides together.

- `README.md` and the code (`tests/test_readme.py`): the code point count is checked, every CLI option appears in the CLI Reference, and the example output is what the tool really prints.
- The documentation says what is scanned by rule. It does not list languages, extensions or file names as supported, in the README, the changelog or anywhere else; a test fails when the README names one from the selection lists.
- `characters.py` and the Unicode property data (`tests/test_unicode_data.py`, which needs `regex`): the detection set, the format characters left out on purpose, and the emoji ranges. `regex` is pinned in `pyproject.toml`. The Renovate pull request that raises it to a release with a newer Unicode version fails these tests; the failure prints what to update.
- Version and requirement parsing in `lockfile.py` and the `packaging` library (`tests/test_requirements_oracle.py`).
- The `heckler` hook in `.pre-commit-hooks.yaml`: `types: [file]` and `--skip-binary` go together (`tests/test_file_selection.py`).
- The `files:` pattern of the `heckler-lockfile` hook in `.pre-commit-hooks.yaml` and `detect_ecosystem()` in `lockfile.py` (`tests/test_lockfile.py`).
- `examples/dependency-scan.yml` (`tests/test_examples.py`): its two trigger lists and the lockfiles its install step handles are the same set, and the promises in its header (no package scripts, wheels only, no cache, a read-only token) are checked.
- `CHANGELOG.md` follows Keep a Changelog. User-visible changes go under `[Unreleased]` as one-line entries that describe behaviour.

## Tests and fixtures

- Fixtures are inert. A sample is flagged characters sitting in a comment or a string, read back by nothing: no decoders, no working attack samples, no fixture that executes.
- Tests do not touch the network, and nothing is downloaded to verify a change. The vet tests replace `download_package` with archives built in `tmp_path`; the lockfile tests stage a real lockfile in this repository and clean up after themselves.
- No file in the repository may hold a literal invisible character, since the self-scan runs in CI. Build them with `chr(0x200B)` and the like. An escape sequence can reach the disk as the literal character depending on how the file was written, so after creating or editing a file that is meant to hold one, run the self-scan and `grep -nP '[^\x00-\x7F]'` on it.
- Hand-aligned data tables are wrapped in `# fmt: off` / `# fmt: on`; leave the formatter out of them.

## Commits and releases

- Commit subjects follow Conventional Commits (`fix(scanner): ...`); the commit-msg hook rejects anything else. `main` takes changes through pull requests only.
- Versions follow Semantic Versioning, and `CONTRIBUTING.md` says what counts as MAJOR, MINOR and PATCH for this tool. The version lives in `src/heckler/_version.py`.
- A release is a tag of the form `vMAJOR.MINOR.PATCH` on `main`. `.github/workflows/release.yml` runs for no other tag, and stops before publishing when the tag does not match `_version.py` or `CHANGELOG.md` has no section for the version. It publishes to PyPI and creates the GitHub release. The tag is signed (`git tag -s`), and full versions are the only tags: there is no major tag such as `v1`.
