"""Facts a rule page states: platform profiles, every block setting, deployment targets."""

from __future__ import annotations

from typing import Any

import pytest

from opentide.documentation.facts.deployment import (
    StaticEnvironment,
    StatusDefinition,
    TenantInfo,
    rule_deployments,
)
from opentide.documentation.facts.platforms import EQL, ESQL, KQL, KUERY, LUCENE, PROFILES
from opentide.documentation.facts.settings import flatten
from opentide.models.deployment_enums import StatusStrategy
from opentide.models.platform import ElasticConfig, RuleConfigurations, SentinelConfig
from opentide.models.rule import DetectionRule

_SENTINEL: dict[str, Any] = {
    "enabled": True,
    "name": "Sentinel name",
    "status": "STAGING",
    "tenants": ["blue"],
    "query": "SecurityEvent\n| take 1\n",
    "scheduling": {"frequency": "PT1H", "lookback": "PT2H"},
    "alert": {"title": "Alert | title", "suppression": False},
    "exclusions": [
        {"tenant": "blue", "reason": "Service account", "query": "| where Account != 'svc'"}
    ],
    "entities": [{"entity": "Account", "mappings": [{"identifier": "Name", "column": "Identity"}]}],
}

_STATUSES = (
    StatusDefinition("STAGING", "Under test", StatusStrategy.PREVIEW),
    StatusDefinition("PRODUCTION", "Live", StatusStrategy.RELEASE),
    StatusDefinition("RETIRED", "Gone", StatusStrategy.DELETION),
    StatusDefinition("DRAFT", "Not deployed", StatusStrategy.INERT),
)


def _rule(rule_payload: dict[str, Any], **blocks: dict[str, Any]) -> DetectionRule:
    return DetectionRule.from_yaml_dict({**rule_payload, "configurations": blocks})


def test_every_rule_platform_has_a_profile() -> None:
    """A platform added to the rule model must say how its page names it."""
    assert set(RuleConfigurations.model_fields) == set(PROFILES)


@pytest.mark.parametrize(
    ("block", "language"),
    [
        ({"type": "eql", "query": "process where true"}, EQL),
        ({"type": "esql", "query": "FROM logs-*"}, ESQL),
        ({"type": "query", "query": "a:b", "language": "lucene"}, LUCENE),
        ({"type": "query", "query": "a:b"}, KUERY),
    ],
)
def test_elastic_query_language_follows_the_rule_type(
    block: dict[str, Any], language: object
) -> None:
    config = ElasticConfig.model_validate({"status": "STAGING", **block})
    assert PROFILES["elastic"].language("query", config) == language


def test_flatten_documents_every_value_the_block_holds() -> None:
    block = SentinelConfig.model_validate(_SENTINEL)
    settings = flatten(
        block,
        exclude=("enabled", "status", "tenants"),
        code_language=lambda path: PROFILES["sentinel"].language(path, block),
    )
    rows = {row.path: row for row in settings.rows}
    # Words are prose, identifiers are code.
    assert rows["name"].value == "Sentinel name"
    assert rows["scheduling.frequency"].value == "`PT1H`"
    assert rows["alert.suppression"].value == "`false`"
    assert rows["alert.title"].description
    assert "status" not in rows and "tenants" not in rows
    # Exclusions hold a query, so each is walked and its query fenced, not tabled.
    assert rows["exclusions[0].tenant"].value == "`blue`"
    assert rows["exclusions[0].reason"].value == "Service account"
    # A pipe is not plain language: the value stays code, the table escapes it.
    assert rows["alert.title"].value == "`Alert | title`"
    code = {item.path: item for item in settings.code}
    assert code["query"].language == KQL
    assert code["query"].code == "SecurityEvent\n| take 1"
    assert code["exclusions[0].query"].language == KQL
    # A list of flat objects becomes one table.
    tables = {table.path: table for table in settings.tables}
    mappings = tables["entities[0].mappings"]
    assert mappings.columns == ("identifier", "column")
    assert mappings.rows == (("`Name`", "`Identity`"),)
    assert rows["entities[0].entity"].value == "`Account`"


def test_flatten_marks_defaults_the_author_did_not_write() -> None:
    config = ElasticConfig.model_validate({"status": "STAGING", "type": "query", "query": "a"})
    rows = {row.path: row for row in flatten(config).rows}
    assert rows["building_block"].default
    assert not rows["type"].default
    assert "index" not in rows


def test_listed_tenants_are_the_only_targets(rule_payload: dict[str, Any]) -> None:
    rule = _rule(rule_payload, sentinel=_SENTINEL)
    environment = StaticEnvironment(
        status_definitions=_STATUSES,
        enabled_platforms=frozenset({"sentinel"}),
        platform_tenants={
            "sentinel": (
                TenantInfo("blue", "Blue team", (StatusStrategy.PREVIEW,)),
                TenantInfo("red"),
            )
        },
        states={rule.metadata.uuid: {"sentinel": {"blue": "rule-1", "old": "rule-0"}}},
    )
    (deployment,) = rule_deployments(rule, environment)
    assert deployment.label == "Microsoft Sentinel"
    assert deployment.strategy is StatusStrategy.PREVIEW
    assert deployment.runs == (StatusStrategy.PREVIEW,)
    assert deployment.scope == "listed"
    assert [(t.name, t.runs, t.remote_id) for t in deployment.targets] == [
        ("blue", (StatusStrategy.PREVIEW,), "rule-1")
    ]
    assert dict(deployment.orphaned_ids) == {"old": "rule-0"}
    assert deployment.platform_enabled is True


def test_unlisted_blocks_reach_every_tenant_that_is_not_manual(
    rule_payload: dict[str, Any],
) -> None:
    block = {**_SENTINEL, "status": "PRODUCTION"}
    del block["tenants"]
    rule = _rule(rule_payload, sentinel=block)
    environment = StaticEnvironment(
        status_definitions=_STATUSES,
        platform_tenants={
            "sentinel": (
                TenantInfo("preview-only", strategies=(StatusStrategy.PREVIEW,)),
                TenantInfo("prod"),
                TenantInfo("hand-picked", manual=True),
            )
        },
    )
    (deployment,) = rule_deployments(rule, environment)
    assert deployment.scope == "all"
    assert [target.name for target in deployment.targets] == ["preview-only", "prod"]
    assert [target.name for target in deployment.reached] == ["prod"]
    assert deployment.platform_enabled is None


@pytest.mark.parametrize(
    ("status", "runs"),
    [
        ("RETIRED", (StatusStrategy.RELEASE,)),
        ("DRAFT", ()),
        ("UNDEFINED", ()),
    ],
)
def test_runs_follow_the_status_strategy(
    rule_payload: dict[str, Any], status: str, runs: tuple[StatusStrategy, ...]
) -> None:
    rule = _rule(rule_payload, sentinel={**_SENTINEL, "status": status})
    (deployment,) = rule_deployments(rule, StaticEnvironment(status_definitions=_STATUSES))
    assert deployment.runs == runs
    assert (deployment.definition is None) == (status == "UNDEFINED")


def test_unreadable_and_empty_tenant_configuration(rule_payload: dict[str, Any]) -> None:
    rule = _rule(rule_payload, sentinel=_SENTINEL)
    (unknown,) = rule_deployments(rule, StaticEnvironment(status_definitions=_STATUSES))
    assert unknown.scope == "listed"
    assert [target.name for target in unknown.targets] == ["blue"]

    environment = StaticEnvironment(status_definitions=_STATUSES, platform_tenants={"sentinel": ()})
    (none,) = rule_deployments(rule, environment)
    assert none.scope == "none"
    assert none.unknown_tenants == ("blue",)


def test_a_rule_without_configurations_deploys_nowhere(rule_payload: dict[str, Any]) -> None:
    rule = DetectionRule.from_yaml_dict(rule_payload)
    assert rule_deployments(rule, StaticEnvironment()) == []


def test_live_tenants_are_read_without_resolving_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Building the typed configuration resolved every $VAR and failed a debug run."""
    from opentide.documentation.facts import deployment

    systems = {
        "sentinel": {
            "tenants": [
                {
                    "name": "a",
                    "description": "A",
                    "strategies": "PREVIEW",
                    "setup": {"x": "$UNSET"},
                },
                {"name": "b", "manual": True},
            ]
        },
        "splunk": {"tenants": [{"name": "c", "strategies": ["NOT-A-STRATEGY"]}]},
        "elastic": {"tenants": [{"description": "nameless"}]},
        "sysdig": {},
    }
    monkeypatch.setattr("opentide.platforms.config.systems_raw_index", lambda: systems)
    assert deployment._read_tenants("sentinel") == (
        TenantInfo("a", "A", (StatusStrategy.PREVIEW,)),
        TenantInfo("b", "", (StatusStrategy.PREVIEW, StatusStrategy.RELEASE), manual=True),
    )
    assert deployment._read_tenants("splunk") is None
    assert deployment._read_tenants("elastic") is None
    assert deployment._read_tenants("sysdig") == ()
    assert deployment._read_tenants("crowdstrike") is None


def test_live_environment_caches_tenants_and_tolerates_a_broken_state_shard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from opentide.documentation.facts.deployment import LiveEnvironment
    from opentide.states.deployment import DeploymentState, DeploymentStateError

    calls: list[str] = []
    monkeypatch.setattr(
        "opentide.documentation.facts.deployment._read_tenants",
        lambda platform: calls.append(platform) or (),
    )

    def broken(*_args: object, **_kwargs: object) -> DeploymentState:
        raise DeploymentStateError("deployment_state_shape", "bad")

    monkeypatch.setattr(DeploymentState, "load", broken)
    environment = LiveEnvironment()
    assert environment.tenants("sentinel") == ()
    assert environment.tenants("sentinel") == ()
    assert calls == ["sentinel"]
    assert environment.remote_ids("00000000-0000-4000-8000-000000000001") == {}


@pytest.mark.parametrize(
    ("value", "rendered"),
    [
        (
            "Corporate VPN egress is hosted on a cloud provider.",
            "Corporate VPN egress is hosted on a cloud provider.",
        ),
        ("0 * * * *", "`0 * * * *`"),
        ("{{Account}} signed in from {{IP}}", "`{{Account}} signed in from {{IP}}`"),
        ("SingleAlert", "`SingleAlert`"),
        ("search count > 0", "`search count > 0`"),
        ("PT1H", "`PT1H`"),
    ],
)
def test_plain_language_is_text_and_everything_else_is_code(value: str, rendered: str) -> None:
    """A cron expression written as text lost its asterisks to emphasis."""
    from opentide.documentation.facts.settings import _scalar

    assert _scalar(value) == rendered
