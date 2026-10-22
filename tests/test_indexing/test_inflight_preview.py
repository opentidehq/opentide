"""Inflight shards reach preview output only; every other command reads the files."""

from __future__ import annotations

import json
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from tests.corpus_support import (
    CORPUS_RULE_UUIDS,
    clear_runtime_caches,
    materialise_corpus,
    real_rules_folder,
)
from typer.testing import CliRunner

from opentide.indexing.inflight import inflight_preview, inflight_preview_enabled
from opentide.indexing.inflight_change import build_shard_payload

SENTINEL_UUID = CORPUS_RULE_UUIDS["sentinel"]
NEW_RULE_UUID = "00000000-0000-4000-8003-000000000777"


def _write_shard(repo: Path, body: dict[str, Any]) -> None:
    inflight = repo / ".opentide" / "inflight"
    inflight.mkdir(parents=True, exist_ok=True)
    shard = build_shard_payload(body, "objects/rules/elsewhere.yaml")
    (inflight / f"{body['metadata']['uuid']}.json").write_text(
        json.dumps(shard, default=str), encoding="utf-8"
    )


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """The corpus with two open pull requests' shards on it.

    One rewrites the committed Sentinel rule's query at a higher version, the
    other adds a rule that has no file in this checkout.
    """
    corpus = materialise_corpus(tmp_path / "corpus")
    root = tmp_path / "repo"
    root.mkdir()
    shutil.copytree(corpus / ".opentide", root / ".opentide")
    shutil.copytree(real_rules_folder(corpus), root / "objects" / "rules")
    for family in ("objectives", "threats"):
        shutil.copytree(corpus / "objects" / family, root / "objects" / family)

    committed = yaml.safe_load(
        (root / "objects" / "rules" / "rule-0001-sentinel-kql.yaml").read_text(encoding="utf-8")
    )
    rewritten = json.loads(json.dumps(committed, default=str))
    rewritten["metadata"]["version"] = committed["metadata"]["version"] + 1
    rewritten["configurations"]["sentinel"]["query"] = "UNREVIEWED_QUERY | take 1\n"
    _write_shard(root, rewritten)
    added = json.loads(json.dumps(committed, default=str))
    added["metadata"]["uuid"] = NEW_RULE_UUID
    added["name"] = "Rule from another pull request"
    _write_shard(root, added)

    for name in ("CI", "GITHUB_ACTIONS", "TF_BUILD"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(root))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(root))
    monkeypatch.chdir(root)
    clear_runtime_caches()
    yield root
    clear_runtime_caches()


def _sentinel_query() -> str:
    from opentide.core.registry import Opentide

    return Opentide.Models.rules[SENTINEL_UUID]["configurations"]["sentinel"]["query"]


def test_registry_reads_the_files_on_disk_outside_the_preview(repo: Path) -> None:
    """Every registry build applied the shards, so deploy and validate read them.

    A RELEASE deploy shipped another open pull request's unreviewed query in
    place of the committed file, and ``validate --strict`` checked a shard
    instead of a broken file of the same UUID.
    """
    from opentide.core.registry import Opentide

    assert not inflight_preview_enabled()
    assert "UNREVIEWED_QUERY" not in _sentinel_query()
    assert NEW_RULE_UUID not in Opentide.Models.rules
    assert NEW_RULE_UUID not in Opentide.Rules


def test_preview_overlays_the_shards_and_drops_them_after(repo: Path) -> None:
    from opentide.core.registry import Opentide

    assert "UNREVIEWED_QUERY" not in _sentinel_query()

    with inflight_preview():
        assert inflight_preview_enabled()
        assert _sentinel_query() == "UNREVIEWED_QUERY | take 1\n"
        assert NEW_RULE_UUID in Opentide.Models.rules
        assert Opentide.Rules[NEW_RULE_UUID].name == "Rule from another pull request"

    assert not inflight_preview_enabled()
    assert "UNREVIEWED_QUERY" not in _sentinel_query()
    assert NEW_RULE_UUID not in Opentide.Models.rules


def test_validate_strict_checks_the_file_not_a_shard(repo: Path) -> None:
    """A broken rule passed ``validate --strict`` when a shard had the same UUID."""
    from opentide.cli import app

    rule = repo / "objects" / "rules" / "rule-0001-sentinel-kql.yaml"
    rule.write_text(
        rule.read_text(encoding="utf-8").replace(
            "severity: Substantial incident", "severity: NOT_A_SEVERITY\nbogus_field: 1"
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["--json", "validate", "--strict"])

    assert result.exit_code == 1, result.stdout
    issues = json.loads(result.stdout)["report"]["issues"]
    assert any(issue.get("object_uuid") == SENTINEL_UUID for issue in issues)
    assert all(issue.get("object_uuid") != NEW_RULE_UUID for issue in issues)
