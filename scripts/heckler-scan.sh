#!/usr/bin/env bash
# heckler-scan.sh — Zero-dependency shell fallback for detecting dangerous invisible Unicode.
# Requires GNU grep with PCRE support (grep -P). macOS users: brew install grep
# Usage: ./heckler-scan.sh [directory]    (defaults to current dir)
# Exit code 1 if findings detected (CI-friendly)
#
# PATTERN below is the same character list the Python scanner reports at its
# default severity, and INCLUDES the same file names it scans by default;
# tests/test_coverage.py fails if either drifts apart. What this script
# cannot do: severities, allowlists, suppression comments, or telling an
# emoji's variation selector from a hidden one.

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

# The pattern only works when grep reads its input as UTF-8. In the C/POSIX
# locale, which is what a bare container has, grep rejects the pattern
# outright. A scan that cannot run must not be reported as clean, so try the
# pattern on a known sample (a zero width space) before trusting it.
matches_sample() {
  printf 'a\xe2\x80\x8bb\n' | grep -qaP "$PATTERN" 2>/dev/null
}
if ! matches_sample; then
  export LC_ALL=C.UTF-8
  if ! matches_sample; then
    echo "Error: grep cannot match Unicode characters in this locale." >&2
    echo "  Set a UTF-8 locale, for example: LC_ALL=en_US.UTF-8 $0 $TARGET" >&2
    exit 2
  fi
fi

# The file names the Python scanner looks at by default: its extension list,
# the well-known names without one (Makefile, Dockerfile, .env) and their
# dotted variants (Dockerfile.dev, .env.example). The list is generated; to
# change it, edit the lists in src/heckler/scanner.py and run
# scripts/sync_shell_includes.py. grep compares names case-sensitively, so
# unlike the Python scanner this does not pick up "MAIN.JS" or "script.R".
# BEGIN GENERATED INCLUDES: written by scripts/sync_shell_includes.py, do not edit
INCLUDES=(
  --include='*.ada' --include='*.adb' --include='*.ads' --include='*.asm'
  --include='*.bash' --include='*.bat' --include='*.c' --include='*.cc'
  --include='*.cfg' --include='*.cjs' --include='*.cl' --include='*.clj'
  --include='*.cljc' --include='*.cljs' --include='*.cmake' --include='*.cmd'
  --include='*.conf' --include='*.cpp' --include='*.cr' --include='*.cs'
  --include='*.css' --include='*.cts' --include='*.d' --include='*.dart'
  --include='*.dockerfile' --include='*.edn' --include='*.ejs'
  --include='*.el' --include='*.elm' --include='*.erb' --include='*.erl'
  --include='*.ex' --include='*.exs' --include='*.f03' --include='*.f90'
  --include='*.f95' --include='*.fish' --include='*.go' --include='*.gql'
  --include='*.gradle' --include='*.graphql' --include='*.groovy'
  --include='*.h' --include='*.hbs' --include='*.hcl' --include='*.hh'
  --include='*.hpp' --include='*.hrl' --include='*.hs' --include='*.htm'
  --include='*.html' --include='*.ini' --include='*.ipynb' --include='*.java'
  --include='*.jinja' --include='*.jl' --include='*.js' --include='*.json'
  --include='*.jsx' --include='*.kt' --include='*.lhs' --include='*.lisp'
  --include='*.lua' --include='*.m' --include='*.md' --include='*.mdc'
  --include='*.mjs' --include='*.mk' --include='*.ml' --include='*.mli'
  --include='*.mm' --include='*.mts' --include='*.nim' --include='*.njk'
  --include='*.pas' --include='*.php' --include='*.pl' --include='*.pp'
  --include='*.properties' --include='*.proto' --include='*.ps1'
  --include='*.pth' --include='*.pug' --include='*.purs' --include='*.py'
  --include='*.pyi' --include='*.r' --include='*.rake' --include='*.rb'
  --include='*.rkt' --include='*.rs' --include='*.s' --include='*.scala'
  --include='*.scss' --include='*.sh' --include='*.sql' --include='*.svelte'
  --include='*.swift' --include='*.tcl' --include='*.tf' --include='*.toml'
  --include='*.ts' --include='*.tsx' --include='*.txt' --include='*.v'
  --include='*.vb' --include='*.vbs' --include='*.vue' --include='*.xml'
  --include='*.yaml' --include='*.yml' --include='*.zig' --include='*.zsh'
  --include='.babelrc' --include='.clinerules' --include='.cursorrules'
  --include='.dockerignore' --include='.env' --include='.eslintrc'
  --include='.gitattributes' --include='.gitignore' --include='.gitmodules'
  --include='.npmignore' --include='.prettierrc' --include='.windsurfrules'
  --include='Appfile' --include='BUILD' --include='Berksfile'
  --include='Brewfile' --include='Cakefile' --include='Dangerfile'
  --include='Dockerfile' --include='Fastfile' --include='GNUmakefile'
  --include='Gemfile' --include='Guardfile' --include='Jakefile'
  --include='Jenkinsfile' --include='Justfile' --include='Makefile'
  --include='Matchfile' --include='Podfile' --include='Procfile'
  --include='Rakefile' --include='SConscript' --include='SConstruct'
  --include='Steepfile' --include='Taskfile' --include='Vagrantfile'
  --include='WORKSPACE' --include='justfile' --include='makefile'
  --include='.env.*' --include='Dockerfile.*'
)
# END GENERATED INCLUDES

EXCLUDES=(
  --exclude-dir=node_modules --exclude-dir=vendor --exclude-dir=.git
  --exclude-dir=__pycache__ --exclude-dir=.venv --exclude-dir=venv
  --exclude-dir=dist --exclude-dir=build --exclude-dir=target
  --exclude-dir=site-packages --exclude-dir=coverage
)

# -a: without it grep calls any file holding a NUL byte "binary" and reports
# nothing from it, which would let one byte hide the rest of the file.
RESULTS=$(grep -rPna "$PATTERN" "${INCLUDES[@]}" "${EXCLUDES[@]}" "$TARGET" 2>/dev/null | tr -d '\000' || true)

if [ -n "$RESULTS" ]; then
  COUNT=$(echo "$RESULTS" | wc -l | tr -d ' ')
  echo ""
  echo "Dangerous invisible Unicode characters detected! ($COUNT occurrence(s))"
  echo ""
  # Files first, so one noisy file cannot push the others out of the listing.
  echo "Files:"
  cut -d: -f1 <<<"$RESULTS" | sort | uniq -c | sort -rn | sed -n '1,50p' | cat -v
  echo ""
  # cat -v spells out control and non-ASCII bytes, so the characters being
  # reported are visible and nothing in a scanned file can act on the terminal.
  # Reading from a here-string keeps head from breaking the pipe under pipefail.
  head -50 <<<"$RESULTS" | cat -v | cut -c1-240
  [ "$COUNT" -gt 50 ] && echo "... and $((COUNT - 50)) more."
  echo ""
  echo "Review with: cat -v <file> or hexdump -C <file>"
  exit 1
else
  echo "No dangerous invisible Unicode characters found."
  exit 0
fi
