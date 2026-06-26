#!/usr/bin/env python3
"""Generate ATT&CK vocabularies from STIX bundles."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from opentide.vocabulary.generate_attack import generate_attack_vocabs

SPECIFICATIONS_ENV = "OPENTIDE_SPECIFICATIONS_ROOT"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _specifications_root() -> Path:
    repo_root = _repo_root()
    configured = os.environ.get(SPECIFICATIONS_ENV, str(repo_root.parent / "specifications"))
    return Path(configured).expanduser().resolve()


def _sync_bundled_vocabularies(specifications_root: Path) -> None:
    sync_script = _repo_root() / "scripts" / "build" / "sync_vocabularies.py"
    env = os.environ.copy()
    env[SPECIFICATIONS_ENV] = str(specifications_root)
    subprocess.run([sys.executable, str(sync_script)], check=True, env=env)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate ATT&CK vocabularies from STIX")
    parser.add_argument("--fetch", action="store_true", help="Fetch latest STIX bundles first")
    args = parser.parse_args()
    specifications_root = _specifications_root()
    output_dir = specifications_root / "vocabularies"
    counts = generate_attack_vocabs(fetch=args.fetch, vocab_dir=output_dir)
    _sync_bundled_vocabularies(specifications_root)
    for field, count in counts.items():
        print(f"{field}: {count} entries")
    print(f"synced bundle from: {output_dir}")


if __name__ == "__main__":
    main()
