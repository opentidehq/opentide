#!/usr/bin/env bash
# Fail if vendored parser.c is stale versus grammar.js.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
TS="${TREE_SITTER_CLI:-}"
if [[ -z "$TS" ]]; then
  if [[ -x /tmp/ts-cli/node_modules/.bin/tree-sitter ]]; then
    TS=/tmp/ts-cli/node_modules/.bin/tree-sitter
  else
    TS="$(command -v tree-sitter || true)"
  fi
fi
if [[ -z "$TS" ]]; then
  echo "tree-sitter CLI not found; install tree-sitter-cli"
  exit 1
fi
tmp="$(mktemp -d)"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT
for lang in kql spl esql eql kuery lucene; do
  src="$root/grammars/tree-sitter-opentide-$lang"
  cp -a "$src" "$tmp/$lang"
  (cd "$tmp/$lang" && "$TS" generate)
  if ! diff -u "$src/src/parser.c" "$tmp/$lang/src/parser.c"; then
    echo "parser.c for $lang is stale; run tree-sitter generate"
    exit 1
  fi
  # A grammar with `externals` needs src/scanner.c (crates/opentide-syntax/build.rs
  # compiles it); one without must not carry a stale scanner.
  if tr -d ' \n' < "$src/src/grammar.json" | grep -q '"externals":\[{'; then
    if [[ ! -f "$src/src/scanner.c" ]]; then
      echo "grammar $lang declares externals but has no src/scanner.c"
      exit 1
    fi
  elif [[ -f "$src/src/scanner.c" ]]; then
    echo "grammar $lang has src/scanner.c but declares no externals"
    exit 1
  fi
done
echo "grammars up to date"
