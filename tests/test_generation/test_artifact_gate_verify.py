"""Artifact gate verification behaviour."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide.generation.artifact_gate import verify_generation_checksums


def test_verify_generation_checksums_detects_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = "tide:.opentide/schemas/rule.schema.json"
    file_path = tmp_path / ".opentide" / "schemas" / "rule.schema.json"
    file_path.parent.mkdir(parents=True)
    file_path.write_text('{"changed": true}', encoding="utf-8")
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(tmp_path))
    monkeypatch.setattr(
        "opentide.generation.artifact_gate.resolve_configurations",
        lambda: {
            "paths": {
                "artifacts": {"schemas": {"rule": "rule.schema.json"}, "templates": {}},
            }
        },
    )
    monkeypatch.setattr(
        "opentide.generation.artifact_gate.resolve_workspace_paths",
        lambda: {
            "json_schemas": str(file_path.parent),
            "templates": str(tmp_path / "templates"),
            "platform_templates": str(tmp_path),
        },
    )
    with pytest.raises(AssertionError, match="checksum mismatch"):
        verify_generation_checksums({key: "deadbeef"}, repo_root=tmp_path)
