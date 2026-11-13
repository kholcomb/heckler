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
  review the change, `git add` it, and commit again. A commit that touches
  `src/` is also type checked, by mypy and by Pyright, both in strict mode
  and both over the whole of `src/`. A staged workflow, `action.yml` or
  pre-commit file is checked by zizmor, offline.
- **On the commit message**, the subject line must follow
  [Conventional Commits](https://www.conventionalcommits.org/):
  `type(optional scope): description`, where the type is one of `build`,
  `chore`, `ci`, `docs`, `feat`, `fix`, `perf`, `refactor`, `revert`, `style`
  or `test`. For example: `fix(scanner): scan past NUL bytes`.

To run the lint, format, type check and workflow hooks over the whole tree:

```bash
pre-commit run --all-files
```

## Running Checks

The CI pipeline runs the following on Python 3.11 through 3.14 on Linux, and
on Python 3.12 on Windows and macOS. Please ensure they all pass locally
before opening a pull request. CI also runs the commit hooks and the action
in `action.yml`, uploads the action's scan of the tree to code scanning,
builds the package and installs the wheel, and lints the workflows with
actionlint; there is nothing to run locally for those. A pull request from
a fork cannot upload, so its merge waits on a maintainer.

**Linting (Ruff):**

```bash
ruff check src/ tests/
```

**Formatting (Ruff):**

```bash
ruff format --check src/ tests/
```

**Tests:**

```bash
pytest --cov=heckler --cov-report=term-missing
```

**Type checking:**

```bash
mypy src/
pyright
```

**Workflows**, after a change to a workflow or to `action.yml`. The commit
hook runs the same check on those files when one is staged:

```bash
zizmor --offline .
```

**Self-scan:**

```bash
heckler --ci --severity low .
```

## Code Style

- Heckler is a zero-dependency package. Do not add runtime dependencies.
- Target Python 3.11+. Avoid syntax or stdlib features from later versions.
- Ruff enforces a line length of 100 and the rule sets E, F, W, I, UP, B, and
  SIM. Running `ruff check` before committing will catch most style issues.
- Code is formatted with `ruff format`; the commit hook applies it. Data
  tables that are aligned by hand are wrapped in `# fmt: off` / `# fmt: on`.
- Mypy is configured in strict mode. All public functions should have type
  annotations.
- Pyright is configured in strict mode as well, under `[tool.pyright]` in
  `pyproject.toml`, for `src/`. CI and the commit hook run both.

## Dependency Updates

The dev dependencies in `pyproject.toml`, the actions in the workflows and
the hooks in `.pre-commit-config.yaml` are pinned to exact versions.
[Renovate](https://docs.renovatebot.com/) opens a pull request for each
update, once a week, and CI runs on it like on any other. Its settings are in
`.github/renovate.json`. To change a pin by hand, change it to another exact
version.

## Submitting Changes

1. Create a feature branch from `main`.
2. Make your changes in focused commits whose messages follow the
   Conventional Commits format described above.
3. Ensure all checks listed above pass.
4. Open a pull request against `main` with a clear description of what the
   change does and why.

A maintainer will review your pull request as soon as possible.

## Versioning and Releases

Heckler follows [Semantic Versioning](https://semver.org/). The version is
`MAJOR.MINOR.PATCH` in `src/heckler/_version.py`. What a version number makes
a promise about is the interface: the command-line options, exit codes and
output formats, the configuration keys, the library API, the inputs of the
GitHub Action and the ids of the pre-commit hooks.

The level of a release is the highest level of any change merged since the
last release. Ask three questions of each change, in this order:

1. Does a setup that worked have to be edited to keep working? Then the
   change is MAJOR. This covers a command-line option, exit code, output
   format, configuration key, library name, Action input or pre-commit hook
   id that is removed or changes meaning, and a raised minimum Python
   version.
2. Is there something new to use, or can a run that passed now fail with the
   setup unchanged? Then it is MINOR. This covers a new option, key, library
   name, Action input or output field; a new detection; newly scanned files;
   and a fix that makes heckler refuse or fail where it used to pass in
   silence, when the documentation already said it would.
3. Otherwise it is PATCH: a crash or a hang that is fixed, wrong text in a
   message or a label, packaging, documentation, speed.

Four rules go with them:

- Security is not a level. It decides how soon a release is made; the
  questions above decide the number.
- A tag is not part of the interface. Only full versions are tagged.
- A change is judged by what a user can observe, not by its commit type. A
  commit typed `fix` can be MINOR.
- When two answers are defensible, the higher level is taken.

Every change a user can observe has an entry under `[Unreleased]` in
`CHANGELOG.md`, added by the pull request that makes the change. The heading
it is under records its level:

| Heading | Level |
|---|---|
| `Fixed`, `Security` | PATCH |
| `Added`, `Changed`, `Deprecated` | MINOR |
| `Removed` | MAJOR, or MINOR when what is removed is not part of the interface |

Two markings make the level readable where a heading is not enough. Each is
the first thing in the entry, written exactly as shown:

- An entry that is MAJOR by the first question starts with `**MAJOR:** `,
  whatever heading it is under. A change of meaning or a raised minimum
  Python version is under `Changed` and marked this way. For example:
  `**MAJOR:** The exit code for an unreadable file is now 2, not 1`.
- An entry under `Removed` starts with either `**MAJOR:** ` or
  `**Not part of the interface:** `. One that starts with neither is not
  accepted. For example:
  ``**Not part of the interface:** The `v1` tag``.

A fix that is MINOR by the second question has an entry under `Changed` as
well as under `Fixed` or `Security`. The level of a release is read from the
headings and markings present under `[Unreleased]`, and the maintainer
confirms it in the release pull request.

To release:

1. In a pull request, set the version in `src/heckler/_version.py`, move
   the entries under `[Unreleased]` in `CHANGELOG.md` to a
   `[MAJOR.MINOR.PATCH] - YYYY-MM-DD` section, and put the new version in
   the two examples in `README.md` that name one (`uses: kholcomb/heckler@`
   and the pre-commit `rev:`).
2. Once it is merged, tag that commit on `main` as `vMAJOR.MINOR.PATCH` with
   a signed tag (`git tag -s`) and push the tag.

The release workflow runs for a tag of exactly that form and stops before
publishing if the tag does not match `_version.py` or `CHANGELOG.md` has no
section for the version. It publishes to PyPI and creates the GitHub release.

Full versions are the only tags. There is no major tag such as `v1` that
moves with each release, so `uses: kholcomb/heckler@vMAJOR.MINOR.PATCH` names
one release and keeps naming it.

## Reporting Bugs

Please open an issue at
<https://github.com/kholcomb/heckler/issues> with steps to reproduce, expected
behavior, and actual behavior.

## License

By contributing, you agree that your contributions will be licensed under the
MIT License.
