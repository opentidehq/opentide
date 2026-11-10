#!/usr/bin/env bash
# License scan: release artifacts must not contain an oracle reference
# (Microsoft Kusto.Language, a Splunk SDK, an Elastic or Lucene parser, the
# YARA-X compiler crate with its wasmtime, yara-python). The oracles are
# CI-only. `yara-x-parser` and `yara-x-fmt` ship; `yara-x-<version>` is the
# compiler crate's source path, which they never contain.
# Usage: license-scan.sh <file-or-dir>...  (zips, tarballs and .crate files are unpacked)
set -euo pipefail
if [[ $# -eq 0 ]]; then
  echo "usage: $0 <file-or-dir>..."
  exit 2
fi
pattern='kusto[._-]language|splunklib|splunk[-_]sdk|@elastic/esql|kbn-es-query|EqlBaseParser|org/apache/lucene/queryparser|yara-x-[0-9]|yara[-_]python|wasmtime'
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

n=0
while IFS= read -r -d '' file; do
  n=$((n + 1))
  case "$file" in
    *.whl | *.zip | *.nupkg | *.vsix)
      mkdir -p "$scratch/$n" && unzip -q "$file" -d "$scratch/$n" ;;
    *.tar.gz | *.tgz | *.crate)
      mkdir -p "$scratch/$n" && tar -xzf "$file" -C "$scratch/$n" ;;
  esac
done < <(find "$@" -type f -print0)

hits="$(
  {
    find "$@" "$scratch" -type f \( -iname '*kusto*' -o -iname 'splunklib*' -o -iname 'lucene-*.jar' -o -iname 'EqlBase*' -o -iname 'yara_x*.so' -o -iname 'yara.cpython*' \)
    grep -RailE "$pattern" "$@" "$scratch" || true
  } | sort -u
)"
if [[ -n "$hits" ]]; then
  echo "$hits"
  echo "an oracle reference is in the release artifacts"
  exit 1
fi
echo "no oracle references in $n artifact files"
