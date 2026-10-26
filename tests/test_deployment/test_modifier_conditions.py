"""A platform modifier applies when every condition it sets holds."""

from __future__ import annotations

from collections.abc import Sequence
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from opentide.deployment.planning import TideDeployment, modifier_applies
from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.deployment_enums import DetectionPlatforms
from opentide.models.system_config import SystemConfig

Conditions = SystemConfig.Modifiers.Conditions


@pytest.mark.parametrize(
    ("conditions", "status", "tenant", "flags", "applies"),
    [
        pytest.param(Conditions(default=True), "PRODUCTION", "prod", None, True, id="default"),
        pytest.param(Conditions(), "PRODUCTION", "prod", None, False, id="no-condition"),
        pytest.param(Conditions(default=False), "STAGING", "prod", None, False, id="default-off"),
        pytest.param(Conditions(status=["STAGING"]), "STAGING", "prod", None, True, id="status"),
        pytest.param(
            Conditions(status=["STAGING"]), "PRODUCTION", "prod", None, False, id="other-status"
        ),
        pytest.param(Conditions(tenants=["prod"]), "STAGING", "prod", None, True, id="tenant"),
        pytest.param(
            Conditions(tenants=["prod"]), "STAGING", "lab", None, False, id="other-tenant"
        ),
        # ``tenants`` used to replace the status result, so a STAGING-only
        # modifier reached PRODUCTION rules on a listed tenant.
        pytest.param(
            Conditions(status=["STAGING"], tenants=["prod"]),
            "PRODUCTION",
            "prod",
            None,
            False,
            id="tenant-listed-status-not",
        ),
        pytest.param(
            Conditions(status=["STAGING"], tenants=["prod"]),
            "STAGING",
            "prod",
            None,
            True,
            id="status-and-tenant",
        ),
        pytest.param(Conditions(flags=["noisy"]), "STAGING", "prod", ["noisy"], True, id="flag"),
        pytest.param(
            Conditions(flags=["noisy"]), "STAGING", "prod", ["quiet"], False, id="other-flag"
        ),
        # A rule with no flags skipped the flags check, so ``default`` or a
        # status match applied a flags-only modifier to it.
        pytest.param(
            Conditions(flags=["noisy"], default=True),
            "STAGING",
            "prod",
            None,
            False,
            id="flagless-rule-default",
        ),
        pytest.param(
            Conditions(flags=["noisy"], status=["STAGING"]),
            "STAGING",
            "prod",
            [],
            False,
            id="flagless-rule-status",
        ),
        # A matching flag used to override a status that did not match.
        pytest.param(
            Conditions(flags=["noisy"], status=["STAGING"]),
            "PRODUCTION",
            "prod",
            ["noisy"],
            False,
            id="flag-matches-status-not",
        ),
        pytest.param(
            Conditions(default=True, status=["STAGING"]),
            "PRODUCTION",
            "prod",
            None,
            False,
            id="default-narrowed-by-status",
        ),
    ],
)
def test_modifier_applies_when_every_condition_holds(
    conditions: SystemConfig.Modifiers.Conditions,
    status: str,
    tenant: str,
    flags: Sequence[str] | None,
    applies: bool,
) -> None:
    assert modifier_applies(conditions, status=status, tenant=tenant, flags=flags) is applies


def _sentinel_rule(metadata: dict[str, Any], *, status: str) -> Any:
    return load_rule_from_dict(
        {
            "name": "Sentinel Rule",
            "metadata": metadata,
            "description": "desc",
            "configurations": {
                "sentinel": {
                    "status": status,
                    "query": "SecurityEvent | take 1",
                    "alert": {"title": "Title"},
                }
            },
        }
    )


@pytest.mark.parametrize(("status", "title"), [("STAGING", "Lab Title"), ("PRODUCTION", "Title")])
def test_modifiers_resolver_applies_a_status_and_tenant_modifier_only_when_both_hold(
    metadata: dict[str, Any], status: str, title: str
) -> None:
    """A ``status = ["STAGING"]`` modifier scoped to one tenant renamed production rules there."""
    rule = _sentinel_rule(metadata, status=status)
    tide = TideDeployment.__new__(TideDeployment)
    tide.system_configuration_resolver = MagicMock(
        return_value=SimpleNamespace(
            platform=SimpleNamespace(identifier="sentinel"),
            modifiers=[
                SystemConfig.Modifiers(
                    name="Lab prefix",
                    conditions=Conditions(status=["STAGING"], tenants=["Primary"]),
                    modifications={"alert.title": "prefix::Lab "},
                )
            ],
        )
    )

    modified = tide.modifiers_resolver(rule, "Primary", DetectionPlatforms.SENTINEL)

    assert modified.configurations.sentinel is not None
    assert modified.configurations.sentinel.alert.title == title
