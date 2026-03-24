"""Lockfile diff parsing for targeted dependency scanning.

Parses staged lockfile diffs to identify changed packages, then scans
only those package directories — fast enough for pre-commit (<2s).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .scanner import Finding, Scanner


def detect_ecosystem(lockfile_path: str) -> str:
    """Determine ecosystem from lockfile name."""
    name = Path(lockfile_path).name.lower()
    mapping = {
        'package-lock.json': 'npm',
        'yarn.lock': 'yarn',
        'pnpm-lock.yaml': 'pnpm',
        'requirements.txt': 'pip',
        'poetry.lock': 'poetry',
        'pipfile.lock': 'pip',
        'cargo.lock': 'cargo',
        'go.sum': 'go',
        'gemfile.lock': 'ruby',
        'composer.lock': 'composer',
    }
    return mapping.get(name, 'unknown')


def get_lockfile_diff(lockfile_path: str) -> str:
    """Get the staged diff for a lockfile."""
    try:
        result = subprocess.run(
            ['git', 'diff', '--cached', '--', lockfile_path],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout
        # Fall back to unstaged diff
        result = subprocess.run(
            ['git', 'diff', '--', lockfile_path],
            capture_output=True, text=True, timeout=30,
        )
        return result.stdout if result.returncode == 0 else ''
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ''


def parse_changed_packages(diff_text: str, ecosystem: str) -> list[tuple[str, str]]:
    """Parse a lockfile diff to extract (name, version) tuples for added/changed packages."""
    if ecosystem == 'npm':
        return _parse_npm_lockfile_diff(diff_text)
    elif ecosystem in ('pip', 'poetry'):
        return _parse_pip_diff(diff_text)
    elif ecosystem == 'yarn':
        return _parse_yarn_diff(diff_text)
    elif ecosystem == 'pnpm':
        return _parse_pnpm_diff(diff_text)
    elif ecosystem in ('cargo', 'go', 'ruby', 'composer'):
        import sys as _sys
        print(
            f"Warning: {ecosystem} lockfile parsing is not yet supported. "
            f"Changed packages will not be scanned with --diff-only.",
            file=_sys.stderr,
        )
        return []
    return []


def _parse_npm_lockfile_diff(diff_text: str) -> list[tuple[str, str]]:
    """Parse package-lock.json diff for added/changed packages."""
    packages: list[tuple[str, str]] = []
    # Look for added lines like: +    "node_modules/express": {
    for line in diff_text.splitlines():
        if not line.startswith('+'):
            continue
        line = line[1:].strip()
        # Match "node_modules/pkg" or "node_modules/@scope/pkg"
        if '"node_modules/' in line and '": {' in line:
            path = line.split('"node_modules/')[1].split('"')[0]
            packages.append((path, ''))
        # Note: npm version lines inside package entries are not extracted
        # since the package name is already captured from the path key above
    # Deduplicate
    return list(dict.fromkeys(packages))


def _parse_pip_diff(diff_text: str) -> list[tuple[str, str]]:
    """Parse requirements.txt or poetry.lock diff for added packages."""
    packages: list[tuple[str, str]] = []
    for line in diff_text.splitlines():
        if not line.startswith('+') or line.startswith('+++'):
            continue
        content = line[1:].strip()
        if not content or content.startswith('#'):
            continue
        # requirements.txt: package==version
        if '==' in content:
            name, _, version = content.partition('==')
            name = name.split('[')[0].strip().lower()
            packages.append((name, version.strip()))
        elif '>=' in content or '<=' in content or '!=' in content or '~=' in content:
            name = content.split('>')[0].split('<')[0].split('!')[0].split('~')[0]
            name = name.split('[')[0].strip().lower()
            packages.append((name, ''))
        # poetry.lock: name = "package-name"
        elif content.startswith('name = '):
            name = content.split('=', 1)[1].strip().strip('"').strip("'")
            packages.append((name.lower(), ''))
    return list(dict.fromkeys(packages))


def _parse_yarn_diff(diff_text: str) -> list[tuple[str, str]]:
    """Parse yarn.lock diff for added packages."""
    packages: list[tuple[str, str]] = []
    for line in diff_text.splitlines():
        if not line.startswith('+') or line.startswith('+++'):
            continue
        content = line[1:].strip()
        # yarn.lock entries: "package@^version", "package@~version":
        if content.endswith(':') and '@' in content:
            # Handle multi-range entries: "lodash@^4.0.0", "lodash@^4.17.0":
            first_spec = content.rstrip(':').split(',')[0].strip().strip('"').strip("'")
            # Get package name (before last @)
            if first_spec.startswith('@'):
                # Scoped: @scope/name@version
                rest = first_spec[1:]
                name = '@' + rest.rsplit('@', 1)[0] if '@' in rest else first_spec
            else:
                name = first_spec.rsplit('@', 1)[0]
            packages.append((name, ''))
    return list(dict.fromkeys(packages))


def _parse_pnpm_diff(diff_text: str) -> list[tuple[str, str]]:
    """Parse pnpm-lock.yaml diff for added packages."""
    packages: list[tuple[str, str]] = []
    for line in diff_text.splitlines():
        if not line.startswith('+') or line.startswith('+++'):
            continue
        content = line[1:].strip()
        # pnpm format: /@scope/name@version: or /name@version: or /name:
        if not content.startswith('/'):
            continue
        entry = content.lstrip('/').rstrip(':').strip()
        if not entry:
            continue
        if entry.startswith('@'):
            # Scoped: @scope/name@version or @scope/name
            rest = entry[1:]
            after_slash = rest.split('/', 1)[-1] if '/' in rest else rest
            name = '@' + rest.rsplit('@', 1)[0] if '@' in after_slash else entry
        elif '@' in entry:
            # Unscoped with version: name@version
            name = entry.rsplit('@', 1)[0]
        else:
            # Unscoped without version: name
            name = entry
        if name:
            packages.append((name, ''))
    return list(dict.fromkeys(packages))


def resolve_package_dir(
    pkg_name: str,
    ecosystem: str,
    lockfile_path: str,
) -> Path | None:
    """Map a package name to its install directory."""
    lockfile_dir = Path(lockfile_path).parent

    if ecosystem in ('npm', 'yarn', 'pnpm'):
        # Check local node_modules, then walk up for hoisted
        candidate = lockfile_dir / 'node_modules' / pkg_name
        if candidate.is_dir():
            return candidate
        # Walk up for yarn/npm workspaces
        current = lockfile_dir.parent
        for _ in range(5):
            candidate = current / 'node_modules' / pkg_name
            if candidate.is_dir():
                return candidate
            if current.parent == current:
                break
            current = current.parent
        return None

    elif ecosystem in ('pip', 'poetry'):
        # Try to find site-packages
        try:
            result = subprocess.run(
                [sys.executable, '-c', 'import site; print("\\n".join(site.getsitepackages()))'],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                for sp in result.stdout.strip().splitlines():
                    candidate = Path(sp) / pkg_name
                    if candidate.is_dir():
                        return candidate
                    # Try with underscores (pip normalizes hyphens)
                    candidate = Path(sp) / pkg_name.replace('-', '_')
                    if candidate.is_dir():
                        return candidate
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    return None


def scan_changed_deps(lockfile_paths: list[str], scanner: Scanner) -> list[Finding]:
    """Main entry point: parse lockfile diffs and scan only changed packages."""
    all_findings: list[Finding] = []

    for lf_path in lockfile_paths:
        ecosystem = detect_ecosystem(lf_path)
        if ecosystem == 'unknown':
            print(f"Warning: Unknown lockfile format: {lf_path}", file=sys.stderr)
            continue

        diff_text = get_lockfile_diff(lf_path)
        if not diff_text:
            # No diff — try scanning the lockfile's dependency dir entirely
            print(f"Warning: No diff available for {lf_path}. Skipping.", file=sys.stderr)
            continue

        changed = parse_changed_packages(diff_text, ecosystem)
        if not changed:
            continue

        for pkg_name, _version in changed:
            pkg_dir = resolve_package_dir(pkg_name, ecosystem, lf_path)
            if pkg_dir is None:
                print(
                    f"Warning: {pkg_name} changed in {lf_path} but install directory not found. "
                    f"Run your package manager's install command and re-commit.",
                    file=sys.stderr,
                )
                continue
            findings = scanner.scan_path(pkg_dir)
            # Tag findings with package info
            for f in findings:
                f.source = "dependency"
                f.package = pkg_name
            all_findings.extend(findings)

    return all_findings
