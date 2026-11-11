# Contributing to Heckler

Thank you for your interest in contributing to Heckler. This guide covers the
basics of setting up a development environment and submitting changes.

## Development Setup

1. Fork and clone the repository:

   ```bash
   git clone https://github.com/<your-username>/heckler.git
   cd heckler
   ```

2. Create and activate a virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install in editable mode with dev dependencies:

   ```bash
   pip install -e ".[dev]"
   ```

4. Install the commit hooks:

   ```bash
   pre-commit install
   ```

## Commit Hooks

`pre-commit install` sets up two hooks from `.pre-commit-config.yaml`:

- **On commit**, staged Python files are linted with `ruff check --fix` and
  formatted with `ruff format`. If a hook changes a file the commit stops;
  review the change, `git add` it, and commit again.
- **On the commit message**, the subject line must follow
  [Conventional Commits](https://www.conventionalcommits.org/):
  `type(optional scope): description`, where the type is one of `build`,
  `chore`, `ci`, `docs`, `feat`, `fix`, `perf`, `refactor`, `revert`, `style`
  or `test`. For example: `fix(scanner): scan past NUL bytes`.

To run the lint and format hooks over the whole tree:

```bash
pre-commit run --all-files
```

## Running Checks

The CI pipeline runs the following on Python 3.9 through 3.13. Please ensure
they all pass locally before opening a pull request.

**Linting (Ruff):**

```bash
ruff check src/ tests/
```

**Tests:**

```bash
pytest --cov=heckler --cov-report=term-missing
```

**Type checking:**

```bash
mypy src/
```

**Self-scan:**

```bash
heckler --ci --severity low .
```

## Code Style

- Heckler is a zero-dependency package. Do not add runtime dependencies.
- Target Python 3.9+. Avoid syntax or stdlib features from later versions.
- Ruff enforces a line length of 100 and the rule sets E, F, W, I, UP, B, and
  SIM. Running `ruff check` before committing will catch most style issues.
- Code is formatted with `ruff format`; the commit hook applies it. Data
  tables that are aligned by hand are wrapped in `# fmt: off` / `# fmt: on`.
- Mypy is configured in strict mode. All public functions should have type
  annotations.

## Submitting Changes

1. Create a feature branch from `main`.
2. Make your changes in focused commits whose messages follow the
   Conventional Commits format described above.
3. Ensure all checks listed above pass.
4. Open a pull request against `main` with a clear description of what the
   change does and why.

A maintainer will review your pull request as soon as possible.

## Reporting Bugs

Please open an issue at
<https://github.com/kholcomb/heckler/issues> with steps to reproduce, expected
behavior, and actual behavior.

## License

By contributing, you agree that your contributions will be licensed under the
MIT License.
