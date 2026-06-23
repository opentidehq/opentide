#!/usr/bin/env python3
"""Generate ATT&CK vocabularies from STIX bundles."""

from __future__ import annotations

import argparse

from opentide.vocabulary.generate_attack import generate_attack_vocabs


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate ATT&CK vocabularies from STIX")
    parser.add_argument("--fetch", action="store_true", help="Fetch latest STIX bundles first")
    args = parser.parse_args()
    counts = generate_attack_vocabs(fetch=args.fetch)
    for field, count in counts.items():
        print(f"{field}: {count} entries")


if __name__ == "__main__":
    main()
