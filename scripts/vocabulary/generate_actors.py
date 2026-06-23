#!/usr/bin/env python3
"""Generate actors vocabulary from STIX and MISP."""

from __future__ import annotations

import argparse

from opentide.vocabulary.generate_actors import generate_actors_vocabs


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate actors vocabulary")
    parser.add_argument("--misp-url", default=None)
    args = parser.parse_args()
    count = generate_actors_vocabs(misp_url=args.misp_url)
    print(f"actors: {count} entries")


if __name__ == "__main__":
    main()
