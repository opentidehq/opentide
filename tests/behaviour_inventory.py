"""Load behaviour IDs from the Phase 4 inventory document."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

_INVENTORY_PATH = Path(__file__).resolve().parents[1] / "docs/migration/behaviour-inventory.md"

_BEHAVIOUR_ID_RE = re.compile(r"^\| ([A-Z]{2}-\d+) \|", re.MULTILINE)

_PREFIX_MODULES: dict[str, str] = {
    "JS": "opentide.generation.schema_pipeline",
    "TP": "opentide.generation.template_renderer",
    "VS": "opentide.generation.template_engine",
    "VA": "opentide.validation.pipeline",
    "IX": "opentide.indexing.object_vocab",
}


@lru_cache(maxsize=1)
def load_behaviour_ids() -> tuple[str, ...]:
    text = _INVENTORY_PATH.read_text(encoding="utf-8")
    return tuple(_BEHAVIOUR_ID_RE.findall(text))


def module_for_behaviour(behaviour_id: str) -> str | None:
    prefix = behaviour_id.split("-", 1)[0]
    return _PREFIX_MODULES.get(prefix)
