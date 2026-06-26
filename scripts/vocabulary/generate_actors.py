#!/usr/bin/env python3
"""Generate actors vocabulary from STIX and MISP."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from opentide.vocabulary.generate_actors import generate_actors_vocabs

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
    parser = argparse.ArgumentParser(description="Generate actors vocabulary")
    parser.add_argument("--misp-url", default=None)
    args = parser.parse_args()
    specifications_root = _specifications_root()
    output_dir = specifications_root / "vocabularies"
    count = generate_actors_vocabs(misp_url=args.misp_url, vocab_dir=output_dir)
    _sync_bundled_vocabularies(specifications_root)
    print(f"actors: {count} entries")
    print(f"synced bundle from: {output_dir}")


if __name__ == "__main__":
    main()
