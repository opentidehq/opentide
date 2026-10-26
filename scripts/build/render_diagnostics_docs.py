"""Render docs/cli/diagnostics.md from the explain pages in src/opentide/data/diagnostics/.

Run from the repository root:

    uv run python scripts/build/render_diagnostics_docs.py          # write
    uv run python scripts/build/render_diagnostics_docs.py --check  # exit 1 on drift
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from opentide.cli.services.explain import REFERENCE_PAGE, reference_markdown

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail when the page is stale")
    args = parser.parse_args()
    target = ROOT / REFERENCE_PAGE
    rendered = reference_markdown()
    if args.check:
        current = target.read_text(encoding="utf-8") if target.is_file() else ""
        if current != rendered:
            print(f"{REFERENCE_PAGE} is stale; run {Path(__file__).relative_to(ROOT)}")
            return 1
        return 0
    target.write_text(rendered, encoding="utf-8")
    print(f"wrote {REFERENCE_PAGE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
