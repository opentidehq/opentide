#!/usr/bin/env bash
# Validate docs/ structure for Fumadocs integration.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCS="$ROOT/docs"
ERRORS=0

warn() { echo "WARN: $*" >&2; }
fail() { echo "ERROR: $*" >&2; ERRORS=$((ERRORS + 1)); }

# Required root tabs
for tab in usage cli mcp sdk; do
  if [[ ! -f "$DOCS/$tab/meta.json" ]]; then
    fail "Missing docs/$tab/meta.json"
  fi
  if ! grep -q '"root"[[:space:]]*:[[:space:]]*true' "$DOCS/$tab/meta.json" 2>/dev/null; then
    fail "docs/$tab/meta.json must set root: true"
  fi
done

# Frontmatter on all markdown pages (except README)
while IFS= read -r -d '' file; do
  base="$(basename "$file")"
  [[ "$base" == "README.md" ]] && continue
  if ! head -1 "$file" | grep -q '^---$'; then
    fail "Missing frontmatter: ${file#$ROOT/}"
  fi
done < <(find "$DOCS" -name '*.md' -print0)

# meta.json pages reference existing slugs (no .md extension)
check_meta_pages() {
  local dir="$1"
  local meta="$dir/meta.json"
  [[ -f "$meta" ]] || return 0
  python3 - "$dir" "$meta" <<'PY'
import json, sys
from pathlib import Path

dir_path = Path(sys.argv[1])
meta_path = Path(sys.argv[2])
data = json.loads(meta_path.read_text())
pages = data.get("pages", [])

for entry in pages:
    if not isinstance(entry, str):
        continue
    if entry.startswith("---") or entry.startswith("[") or entry.startswith("external:"):
        continue
    if entry.startswith("!") or entry.startswith("..."):
        continue
    candidate = dir_path / entry
    md = dir_path / f"{entry}.md"
    if candidate.is_dir() or md.is_file() or (dir_path / "index.md").exists() and entry == "index":
        continue
    if md.is_file():
        continue
    # index slug maps to index.md
    if entry == "index" and (dir_path / "index.md").is_file():
        continue
    print(f"orphan meta entry: {meta_path.relative_to(Path.cwd())} -> {entry}", file=sys.stderr)
    sys.exit(1)
PY
  if [[ $? -ne 0 ]]; then ERRORS=$((ERRORS + 1)); fi
}

while IFS= read -r -d '' meta; do
  check_meta_pages "$(dirname "$meta")"
done < <(find "$DOCS" -name 'meta.json' -print0)

# Broken relative markdown links (simple check)
python3 - "$DOCS" <<'PY'
import re, sys
from pathlib import Path

docs = Path(sys.argv[1])
link_re = re.compile(r'\[[^\]]+\]\(([^)]+)\)')
errors = 0

for md in docs.rglob("*.md"):
    text = md.read_text()
    for target in link_re.findall(text):
        if target.startswith(("http://", "https://", "#", "mailto:")):
            continue
        path_part = target.split("#")[0]
        if not path_part:
            continue
        resolved = (md.parent / path_part).resolve()
        if not resolved.exists():
            print(f"broken link in {md.relative_to(docs)}: {target}", file=sys.stderr)
            errors += 1
sys.exit(1 if errors else 0)
PY
if [[ $? -ne 0 ]]; then ERRORS=$((ERRORS + 1)); fi

if [[ "$ERRORS" -gt 0 ]]; then
  echo "validate-docs: $ERRORS error(s)" >&2
  exit 1
fi

echo "validate-docs: OK"
