"""Field docstrings agree with the field tables in the specifications repository.

Skipped without a specifications checkout. Point ``OPENTIDE_SPECIFICATIONS_ROOT``
at one (as the vocabulary drift check does), or clone it next to this repository.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from opentide.models.base import TideModel
from opentide.models.schema_registry import registered_identifiers, resolve_model

_REPO = Path(__file__).resolve().parents[2]
SPECS = Path(os.environ.get("OPENTIDE_SPECIFICATIONS_ROOT", _REPO.parent / "specifications"))
SPEC_FILES = ["platforms/*.md", "objects/*-1.0.md", "metadata.md"]

#: Deliberate rewrites: the spec row points at another spec page, or describes
#: what the spec says rather than what the model enforces.
REWRITTEN = {
    ("DetectionObjective", "metadata"),
    ("DetectionRule", "metadata"),
    ("ElasticActions", "respond"),
    ("ElasticRisk", "score"),
    ("ElasticThreatMatch", "filters"),
    ("ObjectiveBody", "signals"),
    ("ObjectMetadata", "schema_id"),
    ("PlatformConfigBase", "platform_schema"),
    ("PlatformConfigBase", "status"),
    ("RuleResponse", "responders"),
    ("SentinelOneCondition", "cool_off"),
    ("SignalData", "logsources"),
    ("ThreatBody", "actors"),
    ("ThreatVector", "metadata"),
}

_HEADING = re.compile(r"^#{2,4} .*\((\w+)\)\s*$")
_ROW = re.compile(r"^\|\s*`(\w+)`\s*\|")


def _normalise(text: str) -> str:
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text).replace("\\|", "|")
    return " ".join(text.split()).rstrip(".")


def _models() -> dict[str, type[TideModel]]:
    found: dict[str, type[TideModel]] = {}
    todo: list[object] = [resolve_model(schema_id) for schema_id in registered_identifiers()]
    while todo:
        item = todo.pop()
        if isinstance(item, type) and issubclass(item, TideModel):
            if item.__name__ in found:
                continue
            for cls in item.__mro__:
                if isinstance(cls, type) and issubclass(cls, TideModel) and cls is not TideModel:
                    found.setdefault(cls.__name__, cls)
            todo.extend(field.annotation for field in item.model_fields.values())
        todo.extend(getattr(item, "__args__", ()) or ())
    return found


def _spec_rows() -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for pattern in SPEC_FILES:
        for path in sorted((SPECS / "specs").glob(pattern)):
            # Only the first table under a ``### `field` (ClassName)`` heading
            # describes that class; later tables there describe nested objects.
            model: str | None = None
            in_table = False
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.startswith("#"):
                    heading = _HEADING.match(line)
                    model = heading.group(1) if heading else None
                elif line.startswith("|"):
                    if not in_table and not line.rstrip().endswith("Description |"):
                        model = None  # a table without a description column
                    in_table = True
                    if model and (row := _ROW.match(line)):
                        description = re.split(r"(?<!\\)\|", line.strip().strip("|"))[-1]
                        rows.append((model, row.group(1), description))
                elif in_table:
                    in_table, model = False, None
    return rows


@pytest.mark.skipif(not (SPECS / "specs").is_dir(), reason="no specifications checkout")
def test_field_docstrings_match_the_spec_tables() -> None:
    models = _models()
    drift = []
    for model_name, key, spec_text in _spec_rows():
        model = models.get(model_name)
        if model is None:
            continue
        fields = {info.alias or name: name for name, info in model.model_fields.items()}
        name = fields.get(key, key)
        info = model.model_fields.get(name)
        if info is None or (model_name, name) in REWRITTEN:
            continue
        if _normalise(info.description or "") != _normalise(spec_text):
            drift.append(f"{model_name}.{name}: spec {spec_text!r} != {info.description!r}")
    assert drift == []
