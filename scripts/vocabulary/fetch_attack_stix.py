#!/usr/bin/env python3
"""Fetch latest MITRE ATT&CK STIX bundles."""

from __future__ import annotations

import sys
from pathlib import Path

from opentide.core.files import resolve_paths
from opentide.vocabulary.fetch_stix import fetch_latest_attack_stix


def main() -> None:
    paths = resolve_paths()
    output_dir = Path(paths["resources"]) / "attack" / "stix"
    manifest = fetch_latest_attack_stix(output_dir)
    print(f"Fetched ATT&CK STIX {manifest.get('version')} → {output_dir}")
    for key, info in manifest.get("bundles", {}).items():
        print(f"  {key}: {info.get('path')}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
