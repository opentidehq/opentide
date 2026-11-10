#!/bin/bash
# Remove older builds of the same test or bin executable in a cargo deps dir (keep the newest per name; skip anything touched in the last 20 min).
d="$1/debug/deps"; [ -d "$d" ] || exit 0; cd "$d" || exit 1
ls -t | while read f; do
  [ -x "$f" ] && [ -f "$f" ] && case "$f" in *.*) continue;; esac || continue
  n="${f%-*}"; echo "$n $f"
done | awk 'seen[$1]++ {print $2}' | while read f; do
  [ -z "$(find "$f" -mmin -20)" ] && rm -f "$f" "$f.d"
done
