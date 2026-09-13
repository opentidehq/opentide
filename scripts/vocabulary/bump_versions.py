#!/usr/bin/env python3
"""Discover newer ATT&CK STIX releases and optionally regenerate vocabularies.

Delegates to the full ATT&CK + MISP ingest so actors, per-key versions, and
schema pins stay in the same run.
"""

from __future__ import annotations

import sys

from opentide.vocabulary.sync_upstream import cli_main


def main() -> int:
    print(
        "bump_versions.py now runs the full ATT&CK + MISP ingest. "
        "Prefer: uv run python scripts/vocabulary/sync_upstream.py --check|--apply",
        file=sys.stderr,
    )
    forwarded = [arg for arg in sys.argv[1:] if arg]
    if "--apply" not in forwarded and "--check" not in forwarded:
        forwarded.append("--check")
    return cli_main(forwarded)


if __name__ == "__main__":
    raise SystemExit(main())
