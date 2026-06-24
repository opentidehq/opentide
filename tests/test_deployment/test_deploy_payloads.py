"""Unit tests for deploy payload previews using tide_corpus rules."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from opentide.deployment.preview import preview_rule_deployment
from opentide.loading.rule_loader import load_rule_from_dict

ROOT = Path(__file__).resolve().parents[2]
CORPUS_RULES = ROOT / "tests/fixtures/tide_corpus/current/Objects/Detection Rules"


@pytest.fixture
def corpus_sentinel_rule(tide_corpus_env: Path) -> object:
    del tide_corpus_env
    rule_path = CORPUS_RULES / "rule-0001-sentinel-kql.yaml"
    data = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    return load_rule_from_dict(data)


@pytest.fixture
def tide_corpus_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    src = ROOT / "tests/fixtures/tide_corpus/current"
    dest = tmp_path / "corpus"
    shutil.copytree(src, dest)
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(dest))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(dest))
    from opentide.core.root import get_repo_root

    get_repo_root.cache_clear()
    return dest


@pytest.mark.parametrize(
    ("filename", "platform"),
    [
        ("rule-0001-sentinel-kql.yaml", "sentinel"),
        ("rule-0002-defender-kql.yaml", "defender_for_endpoint"),
        ("rule-0003-splunk-spl.yaml", "splunk"),
        ("rule-0004-sentinel-one-s1ql.yaml", "sentinel_one"),
        ("rule-0005-carbon-black-lucene.yaml", "carbon_black_cloud"),
        ("rule-0006-crowdstrike-deploy-only.yaml", "crowdstrike"),
        ("rule-0007-harfanglab-deploy-only.yaml", "harfanglab"),
    ],
)
def test_preview_payload_shape(filename: str, platform: str, snapshot) -> None:
    data = yaml.safe_load((CORPUS_RULES / filename).read_text(encoding="utf-8"))
    rule = load_rule_from_dict(data)
    preview = preview_rule_deployment(platform, rule)
    assert preview["uuid"] == rule.metadata.uuid
    assert preview["api_request"] == snapshot(name=f"{platform}_api_request")
