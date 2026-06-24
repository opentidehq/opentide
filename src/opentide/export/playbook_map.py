"""Playbook mapping export — refactored from Engines/indexing/mdr_playbook_mapper.py."""

from __future__ import annotations

from pathlib import Path

from opentide.core.logging import get_logger
from opentide.core.registry import OpenTide

logger = get_logger(__name__)


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
            logger.warning("no_playbook_entry", name=row["Name"])
        else:
            logger.info("found_playbook_entry", name=row["Name"])

        playbook_mapping.append(row)

    table = pd.DataFrame(playbook_mapping)
    out_path = output or Path("playbook_map.xlsx")
    table.to_excel(out_path, index=False)
    logger.info("playbook_map_written", path=str(out_path))
    return out_path
