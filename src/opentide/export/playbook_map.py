"""Playbook mapping export — refactored from Engines/indexing/mdr_playbook_mapper.py."""

from __future__ import annotations

from pathlib import Path

from opentide.core.logging import log
from opentide.core.registry import OpenTide


def run(output: Path | None = None) -> Path:
    """Generate an Excel playbook mapping for production MDRs."""
    import pandas as pd  # type: ignore[import-untyped]

    OpenTide.initialise()
    playbook_mapping: list[dict[str, str]] = []

    for mdr_uuid, content in OpenTide.Models.rules.items():
        if content.get("status") != "PRODUCTION":
            continue

        row = {
            "File Name": mdr_uuid,
            "Name": content.get("title", ""),
            "Author": content.get("meta", {}).get("author", ""),
            "Playbook": content.get("tags", {}).get("playbook") or "",
        }

        if row["Playbook"] == "":
            log("WARNING", "No playbook entry", row["Name"])
        else:
            log("INFO", "Found playbook entry", row["Name"])

        playbook_mapping.append(row)

    table = pd.DataFrame(playbook_mapping)
    out_path = output or Path("playbook_map.xlsx")
    table.to_excel(out_path, index=False)
    log("SUCCESS", "Playbook map written", str(out_path))
    return out_path
