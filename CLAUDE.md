# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

heckler detects dangerous invisible Unicode in source code and in installed dependencies. It is a zero-dependency Python 3.11+ package that ships as a CLI and library, a GitHub Action and pre-commit hooks.

This file holds what every task needs. The detail is in `AGENTS.md` and the project's own documents; read the part a task touches, when it touches it.

## Every task

Check a change with all six; CI runs the same:

```bash
pytest
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/
pyright
python -m heckler --ci --severity low .
```

One test: `pytest tests/test_scanner.py::TestScanPath::test_skip_dirs`

- Scanning nothing is an error, never a clean result.
- A walk scans every text file. Only being binary leaves a file out, and never one whose name marks it as source.
- No runtime dependencies, and nothing newer than Python 3.11.
- The documentation does not list languages or file types as supported.
- No file may hold a literal invisible character; build them with `chr()`. Fixtures are inert, and tests use no network.

## Read when the task needs it

| Working on | Read |
|---|---|
| Code in `src/heckler/` | `AGENTS.md`: Architecture, and Rules the code is built around |
| File lists, CLI options, the README, the pre-commit hooks, the example workflow | `AGENTS.md`: Things that have to stay in step |
| Tests or fixtures | `AGENTS.md`: Tests and fixtures |
| A commit, a version number or a release | `AGENTS.md`: Commits and releases, then `CONTRIBUTING.md`: Versioning and Releases |
| What an option, exit code or configuration key does for users | `README.md` |
| Why something behaves as it does now | `CHANGELOG.md` |
