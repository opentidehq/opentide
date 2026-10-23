#!/usr/bin/env bash
# CI-only differential oracles (.github/workflows/oracle.yml): the engine
# against Microsoft Kusto.Language (kql) and Splunk's search parser (spl).
# See scripts/oracles/README.md.
#
#   scripts/ci-oracle.sh [kql] [spl]    default: both
#
# Optional locally: a language whose reference is unavailable (no dotnet, or
# no SPLUNK_PASSWORD) is skipped unless OPENTIDE_ORACLE_REQUIRED=1, which CI
# sets. Do not ship Kusto.Language, Splunk, or a Splunk SDK.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
languages=("$@")
[[ ${#languages[@]} -gt 0 ]] || languages=(kql spl)

# The oracles are the only place the references may appear. No Rust, npm or
# Python manifest that feeds a release may depend on them.
manifests=(
  "$root/Cargo.lock" "$root/pyproject.toml" "$root"/crates/*/Cargo.toml
  "$root"/packages/*/package.json "$root"/grammars/*/package.json
)
if grep -IilE 'kusto[._-]language|splunklib|splunk[-_]sdk' "${manifests[@]}"; then
  echo "a shipped manifest depends on an oracle reference"
  exit 1
fi

unavailable() {
  if [[ "${OPENTIDE_ORACLE_REQUIRED:-}" == "1" ]]; then
    echo "$1, and OPENTIDE_ORACLE_REQUIRED=1"
    exit 1
  fi
  echo "$1; skipping (CI runs it)"
}

status=0
for language in "${languages[@]}"; do
  case "$language" in
    kql)
      if ! command -v dotnet >/dev/null 2>&1; then
        unavailable "kql: dotnet not available"
        continue
      fi ;;
    spl)
      if [[ -z "${SPLUNK_PASSWORD:-}" ]]; then
        unavailable "spl: SPLUNK_PASSWORD not set (scripts/oracles/splunk/start.sh)"
        continue
      fi ;;
    *)
      echo "unknown oracle language: $language (kql or spl)"
      exit 2 ;;
  esac
  DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    python3 "$root/scripts/oracles/oracle.py" "$language" || status=1
done
exit "$status"
