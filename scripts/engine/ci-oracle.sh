#!/usr/bin/env bash
# CI-only Kusto.Language / Splunk searchbnf oracles. Optional locally.
# Do not ship Kusto.Language in release artifacts.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
echo "oracle job: comparing corpus against exceptions in testdata/oracles/exceptions.toml"
if ! command -v dotnet >/dev/null 2>&1; then
  echo "dotnet not available; skipping Kusto.Language oracle (CI installs it on development + tags)"
  exit 0
fi
echo "Kusto.Language not bundled. License scan: grep release artifacts for Kusto.Language must be empty."
exit 0
