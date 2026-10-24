"""Unit tests for deploy payload previews using tide_corpus rules."""

from __future__ import annotations

import os
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
        ("rule-0009-elastic-kql.yaml", "elastic"),
    ],
)
def test_preview_payload_shape(
    filename: str, platform: str, snapshot, tide_corpus_repo: Path
) -> None:
    # The Sentinel preview compiles the rule, which resolves ATT&CK techniques
    # through the catalogue index, so the index must be the corpus.
    del tide_corpus_repo
    data = yaml.safe_load((CORPUS_RULES / filename).read_text(encoding="utf-8"))
    rule = load_rule_from_dict(data)
    preview = preview_rule_deployment(platform, rule)
    assert preview["uuid"] == rule.metadata.uuid
    assert preview["api_request"] == snapshot(name=f"{platform}_api_request")


def _sentinel_rule(**sentinel_overrides: object):
    data = yaml.safe_load(
        (CORPUS_RULES / "rule-0001-sentinel-kql.yaml").read_text(encoding="utf-8")
    )
    data["configurations"]["sentinel"].update(sentinel_overrides)
    return load_rule_from_dict(data)


def test_sentinel_preview_is_the_compiled_arm_body(
    tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DEPLOYMENT_ERROR_RAISED", raising=False)
    rule = _sentinel_rule(
        alert={
            "title": "Sentinel KQL Rule",
            "suppression": False,
            "dynamic_properties": [{"property": "ProductName", "column": "ProductName"}],
        }
    )

    preview = preview_rule_deployment("sentinel", rule)

    assert preview["api_request"]["kind"] == "Scheduled"
    override = preview["api_request"]["properties"]["alertDetailsOverride"]
    assert override["alertDynamicProperties"] == [
        {"alertProperty": "ProductName", "value": "ProductName"}
    ]
    assert "error" not in preview
    assert not os.environ.get("DEPLOYMENT_ERROR_RAISED")


def test_sentinel_preview_reports_a_compile_failure(
    tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rule that cannot compile fails the dry-run instead of previewing its config (#545)."""
    monkeypatch.delenv("DEPLOYMENT_ERROR_RAISED", raising=False)
    rule = _sentinel_rule(scheduling={"frequency": "hourly", "lookback": "PT2H"})

    preview = preview_rule_deployment("sentinel", rule)

    assert preview["uuid"] == rule.metadata.uuid
    assert preview["status"] == "failed"
    assert "hourly" in preview["error"]
    assert preview["api_request"] is None
    assert os.environ.get("DEPLOYMENT_ERROR_RAISED") == "1"


def test_sentinel_preview_fails_when_grouping_alert_is_missing(
    tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The deploy-time grouping.alert requirement surfaces in the dry-run too (#549)."""
    monkeypatch.delenv("DEPLOYMENT_ERROR_RAISED", raising=False)
    rule = _sentinel_rule(grouping={"event": "SingleAlert"})

    preview = preview_rule_deployment("sentinel", rule)

    assert preview["status"] == "failed"
    assert preview["error"].startswith("TideRuleDataModelErrors: ")
    assert rule.metadata.uuid in preview["error"]
    assert "configurations.sentinel.grouping.alert is missing" in preview["error"]
    assert os.environ.get("DEPLOYMENT_ERROR_RAISED") == "1"
