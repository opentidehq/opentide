#!/usr/bin/env bash
# CI-only differential oracles (.github/workflows/oracle.yml): the engine
# against Microsoft Kusto.Language (kql), Splunk's search parser (spl),
# @elastic/esql (esql), Elasticsearch's EqlBase.g4 (eql), Kibana's kuery
# grammar.peggy (kuery), Lucene's QueryParser (lucene), and a Carbon Black
# Cloud tenant's search_validation (carbon_black).
# See scripts/engine/oracles/README.md.
#
#   scripts/engine/ci-oracle.sh [kql] [spl] [esql] [eql] [kuery] [lucene] [carbon_black]
#                                                     default: all but carbon_black
#
# Optional locally: a language whose reference is unavailable (no dotnet, no
# SPLUNK_PASSWORD, no node, no java) is skipped unless
# OPENTIDE_ORACLE_REQUIRED=1, which CI sets. Do not ship any reference.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
languages=("$@")
[[ ${#languages[@]} -gt 0 ]] || languages=(kql spl esql eql kuery lucene)

# The oracles are the only place the references may appear. No Rust or npm
# manifest that feeds a release may depend on them.
manifests=(
  "$root/Cargo.lock" "$root"/crates/*/Cargo.toml
  "$root"/packages/*/package.json "$root"/grammars/*/package.json
)
# grep exits 1 for no match and 2 when it cannot read a manifest: only 1 passes,
# so a missing file can never hide a match.
rc=0
grep -IilE 'kusto[._-]language|splunklib|splunk[-_]sdk|@elastic/esql|antlr-ng|peggy|lucene-queryparser' "${manifests[@]}" || rc=$?
if [[ $rc -ne 1 ]]; then
  [[ $rc -eq 0 ]] && echo "a shipped manifest depends on an oracle reference" || echo "could not read every shipped manifest"
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
        unavailable "spl: SPLUNK_PASSWORD not set (scripts/engine/oracles/splunk/start.sh)"
        continue
      fi ;;
    esql | eql | kuery)
      if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
        unavailable "$language: node not available"
        continue
      fi ;;
    lucene)
      if ! command -v java >/dev/null 2>&1; then
        unavailable "lucene: java not available"
        continue
      fi ;;
    carbon_black)
      # A tenant: never on a fork's pull request (oracle.yml).
      if [[ -z "${OPENTIDE_CBC_URL:-}" || -z "${OPENTIDE_CBC_ORG_KEY:-}" || -z "${OPENTIDE_CBC_TOKEN:-}" ]]; then
        unavailable "carbon_black: OPENTIDE_CBC_URL, OPENTIDE_CBC_ORG_KEY or OPENTIDE_CBC_TOKEN not set"
        continue
      fi ;;
    *)
      echo "unknown oracle language: $language (kql, spl, esql, eql, kuery, lucene, or carbon_black)"
      exit 2 ;;
  esac
  DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    python3 "$root/scripts/engine/oracles/oracle.py" "$language" || status=1
done
exit "$status"
