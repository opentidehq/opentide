#!/usr/bin/env python3
"""Discover newer ATT&CK STIX releases and optionally regenerate vocabularies."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.request import Request, urlopen

from opentide.core.files import resolve_paths
from opentide.vocabulary.fetch_stix import GITHUB_API, fetch_latest_attack_stix

from opentide.vocabulary.generate_attack import generate_attack_vocabs


def _latest_remote_version() -> str:
    request = Request(GITHUB_API, headers={"Accept": "application/vnd.github+json"})
    with urlopen(request, timeout=60) as response:
        release = json.loads(response.read().decode("utf-8"))
    tag = str(release.get("tag_name", "unknown"))
    for prefix in ("ATT&CK-v", "ATT&CK-V", "v"):
        if tag.startswith(prefix):
            return tag[len(prefix) :]
    return tag


def _local_version(stix_dir: Path) -> str | None:
    manifest_path = stix_dir / "manifest.json"
    if not manifest_path.is_file():
        return None
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return manifest.get("version")


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Bump ATT&CK STIX vocabulary versions")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Fetch latest STIX and regenerate ATT&CK vocabularies when newer",
    )
    args = parser.parse_args()

    paths = resolve_paths()
    stix_dir = Path(paths["resources"]) / "attack" / "stix"
    local = _local_version(stix_dir)
    remote = _latest_remote_version()

    print(f"Local STIX version:  {local or '(none)'}")
    print(f"Remote STIX version: {remote}")

    if local == remote:
        print("Already up to date.")
        return

    if not args.apply:
        print("Newer version available. Re-run with --apply to fetch and regenerate.")
        return

    fetch_latest_attack_stix(stix_dir)
    counts = generate_attack_vocabs(fetch=False)
    print("Regenerated vocabularies:")
    for field, count in counts.items():
        print(f"  {field}: {count} entries")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
