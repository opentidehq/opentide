"""Schema artifacts survive an interrupted write, and a broken one does not stop the registry."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from opentide.generation import pydantic_schemas
from opentide.registry.builder import RegistryBuilder

PREVIOUS = '{"title": "previous"}\n'


def _interrupt(*args: Any, **kwargs: Any) -> None:
    raise KeyboardInterrupt


def test_an_interrupted_schema_write_keeps_the_previous_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "rule.1.0.schema.json"
    target.write_text(PREVIOUS, encoding="utf-8")

    def truncate_then_stop(self: Path, *args: Any, **kwargs: Any) -> int:
        # What a cancel between open() and write() leaves of a plain write.
        self.open("w", encoding="utf-8").close()
        raise KeyboardInterrupt

    monkeypatch.setattr(Path, "write_text", truncate_then_stop)
    monkeypatch.setattr(os, "replace", _interrupt)
    monkeypatch.setattr(
        pydantic_schemas, "generate_schema_for_identifier", lambda schema_id: {"title": "new"}
    )
    with pytest.raises(KeyboardInterrupt):
        pydantic_schemas.export_schema_for_identifier("rule::1.0", target)
    assert target.read_text(encoding="utf-8") == PREVIOUS
    assert sorted(path.name for path in tmp_path.iterdir()) == [target.name]


def test_a_schema_write_replaces_the_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "rule.1.0.schema.json"
    target.write_text(PREVIOUS, encoding="utf-8")
    monkeypatch.setattr(
        pydantic_schemas, "generate_schema_for_identifier", lambda schema_id: {"title": "new"}
    )
    pydantic_schemas.export_schema_for_identifier("rule::1.0", target)
    assert '"title": "new"' in target.read_text(encoding="utf-8")
    assert sorted(path.name for path in tmp_path.iterdir()) == [target.name]


def test_a_zero_length_schema_artifact_is_skipped_not_raised(tmp_path: Path) -> None:
    (tmp_path / "rule.1.0.schema.json").write_bytes(b"")
    (tmp_path / "threat.1.0.schema.json").write_text('{"title": "threat"}', encoding="utf-8")
    _, schemas = RegistryBuilder()._scan_framework_schemas(
        tmp_path, {"rule": "rule.1.0.schema.json", "threat": "threat.1.0.schema.json"}
    )
    assert "rule::1.0" not in schemas
    assert schemas["threat::1.0"] == {"title": "threat"}
