#!/usr/bin/env bash
# Resolve the latest PMD release on every run, as pmd/pmd-github-action@v2 does.
# Run from any directory; downloaded releases are cached outside the repository.

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cache_root="${XDG_CACHE_HOME:-${HOME}/.cache}/swiyu/pmd"
report_dir="${repo_root}/target/pmd"
report_path="${report_dir}/pmd-report.sarif"

for dependency in curl jq unzip java; do
    if ! command -v "$dependency" >/dev/null 2>&1; then
        echo "Required command not found: $dependency" >&2
        exit 1
    fi
done

mkdir -p -- "$report_dir"
rm -f -- "$report_path"

echo "Resolving the latest PMD release..."
release="$(curl --fail --silent --show-error --location \
    --connect-timeout 15 --max-time 60 \
    https://api.github.com/repos/pmd/pmd/releases/latest)"
version="$(jq --exit-status --raw-output \
    '.tag_name | capture("^pmd_releases/(?<version>[0-9]+\\.[0-9]+\\.[0-9]+)$").version' \
    <<< "$release")"
archive_name="pmd-dist-${version}-bin.zip"
download_url="$(jq --exit-status --raw-output --arg name "$archive_name" \
    '.assets[] | select(.name == $name) | .browser_download_url' <<< "$release")"
pmd_home="${cache_root}/pmd-bin-${version}"

echo "Using PMD ${version} (latest)."
if [[ ! -x "${pmd_home}/bin/pmd" ]]; then
    mkdir -p -- "$cache_root"
    download_dir="$(mktemp -d "${cache_root}/.download.XXXXXXXX")"
    trap 'rm -rf -- "$download_dir"' EXIT

    echo "Downloading ${archive_name}..."
    curl --fail --silent --show-error --location --retry 2 \
        --connect-timeout 15 --output "${download_dir}/${archive_name}" "$download_url"
    unzip -q "${download_dir}/${archive_name}" -d "$download_dir"
    if [[ ! -x "${download_dir}/pmd-bin-${version}/bin/pmd" ]]; then
        echo "The downloaded PMD distribution does not contain bin/pmd." >&2
        exit 1
    fi
    mv -- "${download_dir}/pmd-bin-${version}" "$pmd_home"
fi

cd -- "$repo_root"
# Match the CI ruleset and complete source scope. Findings are reported without
# failing the command; PMD configuration and processing errors still fail it.
"${pmd_home}/bin/pmd" check \
    --dir test-wallet-application/src,test-wallet-library/src \
    --rulesets .github/rulesets/java/pmd_omni_ruleset.xml \
    --format sarif \
    --report-file "$report_path" \
    --no-cache \
    --no-progress \
    --no-fail-on-violation

findings="$(jq '[.runs[]?.results[]?] | length' "$report_path")"
echo "PMD ${version}: ${findings} findings."
echo "Report: ${report_path}"
