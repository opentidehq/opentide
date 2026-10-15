"""CrowdStrike correlation rule status follows the platform status strategy (#553)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.deployment_enums import StatusStrategy
from opentide.platforms.crowdstrike import deployer as module

ROOT = Path(__file__).resolve().parents[2]
CORPUS_RULES = ROOT / "tests/fixtures/tide_corpus/current/Objects/Detection Rules"
RULE = CORPUS_RULES / "rule-0006-crowdstrike-deploy-only.yaml"
TENANT = SimpleNamespace(name="falcon-prod", setup=SimpleNamespace(customer_id="ABC123-def"))


@pytest.mark.parametrize(
    ("strategy", "expected"),
    [
        (StatusStrategy.DISABLEMENT, "inactive"),
        *[
            (strategy, "active")
            for strategy in StatusStrategy
            if strategy is not StatusStrategy.DISABLEMENT
        ],
    ],
)
def test_status_strategy_maps_to_crowdstrike_status(
    monkeypatch: pytest.MonkeyPatch, strategy: StatusStrategy, expected: str
) -> None:
    monkeypatch.setattr(module, "check_status", lambda _status: strategy)
    data = yaml.safe_load(RULE.read_text(encoding="utf-8"))
    # The corpus rule's trigger is not one the compiler accepts; the status is under test.
    data["configurations"]["crowdstrike"]["details"]["trigger"] = "verbose"
    data["metadata"]["author"] = "detection@example.test"
    rule = load_rule_from_dict(data)

    payload = module.CrowdstrikeDeploy().compile_deployment(data=rule, tenant_config=TENANT)

    assert payload.status == expected
