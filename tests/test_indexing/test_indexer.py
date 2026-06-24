"""Tests for Tide indexer with heavy mocking."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide.indexing.indexer import indexer


@pytest.fixture
def mock_index_environment(tmp_path: Path):
    vocab_dir = tmp_path / "vocabs"
    vocab_dir.mkdir()
    (vocab_dir / "severity.vocab.toml").write_text(
        'name = "Severity"\nfield = "severity"\n[[keys]]\nname = "High"\ndescription = "High"\n',
        encoding="utf-8",
    )
    json_schema_dir = tmp_path / "json_schemas"
    json_schema_dir.mkdir()
    (json_schema_dir / "rule.json").write_text('{"type": "object"}', encoding="utf-8")
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    (templates_dir / "rule.yaml").write_text("name: template\n", encoding="utf-8")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_file = rules_dir / "sample-rule.yaml"
    rule_file.write_text(
        "name: Sample\nmetadata:\n  uuid: rule-uuid-1\n  schema: rule::1.0\n  tlp: clear\n",
        encoding="utf-8",
    )
    index_output = tmp_path / "index.json"
    revisions_path = tmp_path / "revisions.json"
    revisions_path.write_text('{"rule-uuid-1": {"name": "Sample"}}', encoding="utf-8")

    paths = {
        "vocabularies": vocab_dir,
        "json_schemas": json_schema_dir,
        "templates": templates_dir,
        "rule": rules_dir,
        "threat": tmp_path / "threats",
        "objective": tmp_path / "objectives",
        "index_output": index_output,
        "tide_indexes": tmp_path,
        "platform_templates": tmp_path / "platform_templates",
    }
    (tmp_path / "threats").mkdir()
    (tmp_path / "objectives").mkdir()
    (tmp_path / "platform_templates").mkdir()

    config = {
        "global": {
            "paths": {
                "tide": {k: str(v) for k, v in paths.items()},
                "core": {"vocabularies": str(vocab_dir)},
            },
            "metaschemas": ["rule"],
            "json_schemas": {"rule": "rule.json"},
            "templates": {"rule": "rule.yaml"},
            "recomposition": {},
            "objects": ["rule"],
        },
        "documentation": {"icons": {}, "object_names": {"rule": "Detection Rules"}},
    }

    return paths, config, index_output


def _patch_indexer_env(monkeypatch, paths, config) -> None:
    core_paths = {"vocabularies": paths["vocabularies"]}

    monkeypatch.setattr("opentide.indexing.indexer.resolve_configurations", lambda: config)
    monkeypatch.setattr(
        "opentide.indexing.indexer.resolve_paths",
        lambda separate=False: (paths, core_paths) if separate else (paths, core_paths),
    )
    monkeypatch.setattr(
        "opentide.generation.pydantic_metaschema.build_core_schema_source",
        lambda name: {"name": name, "type": "object"},
    )
    monkeypatch.setattr(
        "opentide.generation.pydantic_metaschema.build_definition_index",
        lambda: {"shared": {}},
    )


def test_indexer_builds_vocab_and_objects(mock_index_environment, monkeypatch) -> None:
    paths, config, _index_output = mock_index_environment
    _patch_indexer_env(monkeypatch, paths, config)

    result = indexer(write_index=False)
    assert "vocabs" in result
    assert "severity" in result["vocabs"]
    assert result["objects"]["rule"]["rule-uuid-1"]["name"] == "Sample"
    assert result["files"]["rule-uuid-1"] == "sample-rule.yaml"
    assert "revisions" in result["indexes"]


def test_indexer_writes_index_when_requested(mock_index_environment, monkeypatch) -> None:
    paths, config, index_output = mock_index_environment
    _patch_indexer_env(monkeypatch, paths, config)
    captured: dict[str, object] = {}

    def fake_dump(data, fp, **kwargs):
        captured["keys"] = list(data.keys())
        fp.write("{}")

    monkeypatch.setattr("opentide.indexing.indexer.json.dump", fake_dump)
    indexer(write_index=True)
    assert captured["keys"]
    assert index_output.is_file()


def test_indexer_skips_invalid_vocab_file(mock_index_environment, monkeypatch) -> None:
    paths, config, _ = mock_index_environment
    bad_vocab = paths["vocabularies"] / "broken.vocab.toml"
    bad_vocab.write_text("not valid toml [[", encoding="utf-8")
    _patch_indexer_env(monkeypatch, paths, config)

    result = indexer(write_index=False)
    assert "severity" in result["vocabs"]
