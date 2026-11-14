"""What fills the repository's Actions caches (#841), for cache-report.yml.

GitHub keeps 10 GB of Actions caches per repository and evicts the least
recently used beyond that, so the families pull requests restore can be gone
an hour after a push saved them. This reads the caches, as `gh api --paginate
repos/<repo>/actions/caches --jq '.actions_caches[]'` prints them (one JSON
object a line), and writes Markdown: the total against the limit, the sizes
per ref and per key family on each ref, and the largest entries.

A key's family is the key without its hashes and what follows them (the
toolchain hash and ISO week of an sccache key, the lock hash of a rust-cache
or setup-uv key): `sccache-engine-dev-ubuntu-latest-1-<sha256>-2026-W46` is
`sccache-engine-dev-ubuntu-latest-1`.

    python3 scripts/cache_report.py < caches.jsonl > report.md
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

LIMIT = 10 * 1024**3
# A hex run of eight or more characters starts a key's variable part.
HASH = re.compile(r"-[0-9a-f]{8,}(?:-.*)?$")
LARGEST = 25


@dataclass(frozen=True)
class Cache:
    ref: str
    key: str
    size: int
    last_accessed: str
    created: str

    @property
    def family(self) -> str:
        return family(self.key)


def family(key: str) -> str:
    """The key without its hashes and what follows them."""
    return HASH.sub("", key) or key


def parse(lines: Iterable[str]) -> list[Cache]:
    caches = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        entry = json.loads(line)
        caches.append(
            Cache(
                ref=str(entry.get("ref", "")),
                key=str(entry.get("key", "")),
                size=int(entry.get("size_in_bytes", 0)),
                last_accessed=str(entry.get("last_accessed_at", "")),
                created=str(entry.get("created_at", "")),
            )
        )
    return caches


def _size(size: int) -> str:
    return f"{size / 1024**2:,.0f} MB"


def _share(size: int, total: int) -> str:
    return f"{100 * size / total:.0f}%" if total else "-"


def report(caches: list[Cache]) -> str:
    total = sum(cache.size for cache in caches)
    lines = [
        "# Actions caches",
        "",
        f"{len(caches)} caches, {_size(total)} of the {_size(LIMIT)} GitHub keeps "
        f"({_share(total, LIMIT)}); beyond it, the least recently used are evicted.",
        "",
        "## Per ref",
        "",
        "| Ref | Caches | Size | Share |",
        "|---|---:|---:|---:|",
    ]
    per_ref: dict[str, list[Cache]] = defaultdict(list)
    for cache in caches:
        per_ref[cache.ref].append(cache)
    for ref, entries in sorted(per_ref.items(), key=lambda item: -sum(c.size for c in item[1])):
        size = sum(c.size for c in entries)
        lines.append(f"| `{ref}` | {len(entries)} | {_size(size)} | {_share(size, total)} |")
    lines += [
        "",
        "## Per family, on each ref",
        "",
        "| Ref | Family | Caches | Size | Share | Last used |",
        "|---|---|---:|---:|---:|---|",
    ]
    per_family: dict[tuple[str, str], list[Cache]] = defaultdict(list)
    for cache in caches:
        per_family[(cache.ref, cache.family)].append(cache)
    for (ref, name), entries in sorted(
        per_family.items(), key=lambda item: -sum(c.size for c in item[1])
    ):
        size = sum(c.size for c in entries)
        used = max(c.last_accessed for c in entries)
        lines.append(
            f"| `{ref}` | `{name}` | {len(entries)} | {_size(size)} | "
            f"{_share(size, total)} | {used} |"
        )
    lines += [
        "",
        f"## The {LARGEST} largest caches",
        "",
        "| Ref | Key | Size | Created | Last used |",
        "|---|---|---:|---|---|",
    ]
    for cache in sorted(caches, key=lambda c: -c.size)[:LARGEST]:
        lines.append(
            f"| `{cache.ref}` | `{cache.key}` | {_size(cache.size)} | {cache.created} | "
            f"{cache.last_accessed} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    sys.stdout.write(report(parse(sys.stdin)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
