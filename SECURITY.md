# Security Policy

## Supported Versions

| Version | Support Level |
|---------|--------------|
| The newest release | Supported -- security fixes arrive here |
| Any older release  | Not patched -- fixed by upgrading to the newest release |

## Reporting a Vulnerability

Please report vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/kholcomb/heckler/security/advisories/new).
Do not open public issues for security reports.

We will acknowledge your report within **48 hours**.

A fix reaches you in a release, so the targets are for releases. For a
critical issue we target a release that contains the fix within **14 days**
of the report. Once a security fix is merged, the release that contains it
follows within **7 days**, whatever the severity, and is not held for other
work. A fix for a vulnerability reported in private is merged and released
on the same day.

Each vulnerability a release fixes has a
[GitHub security advisory](https://github.com/kholcomb/heckler/security/advisories),
published on the day of the release, which names the versions affected and
the version that fixes it. Releases are pinned by exact version and no tag
moves, so a fix reaches a setup when its pin is changed.

## Scope

The following categories are considered in-scope vulnerabilities:

- **Scanner bypasses** -- crafted input that causes heckler to miss
  dangerous invisible Unicode characters it is designed to detect.
- **Archive extraction path traversal** -- manipulated archives that
  write outside the intended extraction directory during scanning.
- **Dependency confusion in `--vet` mode** -- inputs that trick the
  vetting logic into querying or trusting an unintended package source.
- **Remote code execution during package scanning** -- any code
  execution triggered by processing a package or its metadata.

## Disclosure and Credit

Responsibly disclosed issues will be credited in the
[CHANGELOG](CHANGELOG.md) once a fix is released. If you would like to
be credited under a specific name or handle, please include it in your
report.
