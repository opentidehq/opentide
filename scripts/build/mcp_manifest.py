"""Write crates/opentide-cli/data/mcp/manifest.json: what the Python MCP server says of itself.

The Rust MCP server (UC-3.7, #829) serves the Python server's name,
instructions, capabilities, tools (descriptions and schemas), resources and
resource templates from this file, compiled in. Run from the repository root:

    uv run python scripts/build/mcp_manifest.py          # write
    uv run python scripts/build/mcp_manifest.py --check  # exit 1 on drift
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from opentide.mcp_server.bridge import MANIFEST_PATH, manifest

ROOT = Path(__file__).resolve().parents[2]


def render() -> str:
    """The manifest as the file holds it."""
    return json.dumps(manifest(), indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail when the file is stale")
    args = parser.parse_args()
    target = ROOT / MANIFEST_PATH
    rendered = render()
    if args.check:
        current = target.read_text(encoding="utf-8") if target.is_file() else ""
        if current != rendered:
            print(f"{MANIFEST_PATH} is stale; run {Path(__file__).relative_to(ROOT)}")
            return 1
        return 0
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(rendered, encoding="utf-8", newline="\n")
    print(f"wrote {MANIFEST_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
