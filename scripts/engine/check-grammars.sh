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
for lang in kql spl; do
  src="$root/grammars/tree-sitter-opentide-$lang"
  cp -a "$src" "$tmp/$lang"
  (cd "$tmp/$lang" && "$TS" generate)
  if ! diff -u "$src/src/parser.c" "$tmp/$lang/src/parser.c"; then
    echo "parser.c for $lang is stale; run tree-sitter generate"
    exit 1
  fi
done
echo "grammars up to date"
