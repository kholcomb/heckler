# Security Policy

## Supported Versions

| Version | Support Level |
|---------|--------------|
| 0.3.x   | Supported -- receives security fixes |
| < 0.3.0 | Best-effort -- upgrade recommended |

## Reporting a Vulnerability

Please report vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/kholcomb/heckler/security/advisories/new).
Do not open public issues for security reports.

We will acknowledge your report within **48 hours** and target a fix
within **14 days** for critical issues. Lower-severity issues will be
addressed in the next regular release.

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

## Out of Scope

The `testdata/` directory contains intentionally crafted files with
Unicode sequences and other invisible patterns. These files
exist solely for testing heckler's detection capabilities. Findings in
`testdata/` are not vulnerabilities.

## Disclosure and Credit

Responsibly disclosed issues will be credited in the
[CHANGELOG](CHANGELOG.md) once a fix is released. If you would like to
be credited under a specific name or handle, please include it in your
report.
