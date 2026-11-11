#!/usr/bin/env bash
# heckler-scan.sh — Zero-dependency shell fallback for detecting dangerous invisible Unicode.
# Requires GNU grep with PCRE support (grep -P). macOS users: brew install grep
# Usage: ./heckler-scan.sh [directory]    (defaults to current dir)
# Exit code 1 if findings detected (CI-friendly)
#
# PATTERN below is the same character list the Python scanner reports at its
# default severity; tests/test_coverage.py fails if the two drift apart. What
# this script cannot do: severities, allowlists, suppression comments, or
# telling an emoji's variation selector from a hidden one.

set -euo pipefail

TARGET="${1:-.}"

# Check for PCRE support
if ! echo "test" | grep -P "test" >/dev/null 2>&1; then
  echo "Error: grep -P (PCRE) not supported. Install GNU grep:"
  echo "  macOS: brew install grep (then use ggrep or add to PATH)"
  echo "  Linux: grep should support -P by default"
  exit 2
fi

PATTERN='[\x{0000}-\x{0008}\x{000B}\x{000E}-\x{001F}\x{007F}-\x{00A0}\x{00AD}\x{034F}\x{061C}\x{115F}-\x{1160}\x{1680}\x{17B4}-\x{17B5}\x{180B}-\x{180F}\x{2000}-\x{200F}\x{2028}-\x{202F}\x{205F}-\x{206F}\x{2800}\x{3000}\x{3164}\x{FE00}-\x{FE0F}\x{FEFF}\x{FFA0}\x{FFF0}-\x{FFFC}\x{13441}-\x{13442}\x{16FE4}\x{1BCA0}-\x{1BCA3}\x{1D159}\x{1D173}-\x{1D17A}\x{E0000}-\x{E0FFF}]'

INCLUDES=(
  --include='*.js' --include='*.cjs' --include='*.mjs'
  --include='*.ts' --include='*.jsx' --include='*.tsx'
  --include='*.py' --include='*.rb' --include='*.go' --include='*.rs'
  --include='*.c' --include='*.cpp' --include='*.h' --include='*.java'
  --include='*.cs' --include='*.php' --include='*.sh' --include='*.yaml'
  --include='*.yml' --include='*.json' --include='*.toml' --include='*.xml'
  --include='*.html' --include='*.css' --include='*.sql' --include='*.swift'
  --include='*.kt' --include='*.scala' --include='*.lua' --include='*.md'
)

EXCLUDES=(
  --exclude-dir=node_modules --exclude-dir=vendor --exclude-dir=.git
  --exclude-dir=__pycache__ --exclude-dir=.venv --exclude-dir=venv
  --exclude-dir=dist --exclude-dir=build --exclude-dir=target
  --exclude-dir=site-packages --exclude-dir=coverage
)

RESULTS=$(grep -rPn "$PATTERN" "${INCLUDES[@]}" "${EXCLUDES[@]}" "$TARGET" 2>/dev/null || true)

if [ -n "$RESULTS" ]; then
  COUNT=$(echo "$RESULTS" | wc -l | tr -d ' ')
  echo ""
  echo "Dangerous invisible Unicode characters detected! ($COUNT occurrence(s))"
  echo ""
  echo "$RESULTS" | head -50
  [ "$COUNT" -gt 50 ] && echo "... and $((COUNT - 50)) more."
  echo ""
  echo "Review with: cat -v <file> or hexdump -C <file>"
  exit 1
else
  echo "No dangerous invisible Unicode characters found."
  exit 0
fi
