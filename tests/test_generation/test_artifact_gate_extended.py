"""Extended artifact gate helper coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide.generation.artifact_gate import (
    collect_generation_checksums,
    load_checksum_baseline,
    resolve_artifact_path,
    tide_instance_root,
    write_checksum_baseline,
)


def test_collect_and_verify_checksum_roundtrip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    schema_dir = workspace / ".opentide" / "schemas"
    schema_dir.mkdir(parents=True)
    schema_file = schema_dir / "rule.schema.json"
    schema_file.write_text('{"type":"object"}', encoding="utf-8")

    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(workspace))
    workspace_paths = {
        "json_schemas": str(schema_dir),
        "templates": str(workspace / ".opentide" / "templates"),
        "platform_templates": str(workspace / "subschemas"),
    }
    workspace_config = {
        "artifacts": {
            "schemas": {"rule": "rule.schema.json"},
            "templates": {},
        },
    }
    monkeypatch.setattr(
        "opentide.generation.artifact_gate.resolve_configurations",
        lambda: {"paths": workspace_config},
    )
    monkeypatch.setattr(
        "opentide.generation.artifact_gate.resolve_workspace_paths",
        lambda: workspace_paths,
    )

    checksums = collect_generation_checksums(tmp_path)
    assert any(key.endswith("rule.schema.json") for key in checksums)

    baseline = tmp_path / "baseline.json"
    write_checksum_baseline(checksums, baseline)
    loaded = load_checksum_baseline(baseline)
    assert loaded == checksums

    key = next(k for k in checksums if k.endswith("rule.schema.json"))
    resolved = resolve_artifact_path(key, repo_root=tmp_path)
    assert resolved == schema_file.resolve()


def test_tide_instance_root_defaults_to_parent_when_no_workspace(tmp_path: Path) -> None:
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.delenv("OPENTIDE_TIDE_WORKSPACE", raising=False)
    assert tide_instance_root(tmp_path) == tmp_path.parent.resolve()
    monkeypatch.undo()
