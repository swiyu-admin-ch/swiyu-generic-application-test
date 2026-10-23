#!/usr/bin/env bash
# Extract the CodeQL bundle into <repository>/codeql, install codeql on PATH,
# or set CODEQL_BINARY to the executable. Run this script from any directory.
# https://github.com/github/codeql-action/releases

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
database_path="${repo_root}/swiyu-application-test-codeql-db"
sarif_path="${repo_root}/codeql-results.sarif"
codeql_bin="${CODEQL_BINARY:-${repo_root}/codeql/codeql}"

if [[ -z "${CODEQL_BINARY:-}" && ! -x "$codeql_bin" ]]; then
    codeql_bin="$(command -v codeql || true)"
fi

if [[ -z "$codeql_bin" ]] || ! command -v "$codeql_bin" >/dev/null 2>&1; then
    echo "CodeQL CLI not found. Install the CodeQL bundle or set CODEQL_BINARY." >&2
    exit 1
fi

# Resolve a relative CODEQL_BINARY before changing the working directory.
codeql_bin="$(command -v "$codeql_bin")"
if [[ "$codeql_bin" != /* ]]; then
    codeql_bin="${PWD}/${codeql_bin}"
fi
cd -- "$repo_root"

rm -f -- "$sarif_path"

# Match pull-request-check.yml: no build, so paths-ignore excludes generated clients.
echo "Creating CodeQL database..."
"$codeql_bin" database create "$database_path" \
    --codescanning-config="${repo_root}/.github/codeql/codeql-config.yml" \
    --language=java \
    --build-mode=none \
    --source-root="$repo_root" \
    --overwrite

# With no query arguments, analyze uses the configuration recorded at creation.
echo "Running CodeQL analysis..."
"$codeql_bin" database analyze "$database_path" \
    --format=sarif-latest \
    --output="$sarif_path" \
    --sarif-category="/language:java"

echo "Analysis complete: $sarif_path"
if command -v jq >/dev/null 2>&1; then
    findings="$(jq '[.runs[]?.results[]?] | length' "$sarif_path")"
    echo "Found $findings security/quality issues"
fi
echo "Database: $database_path"
