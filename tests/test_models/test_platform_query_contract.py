"""`query` must mean the same thing on every platform configuration (#233).

The drift was three-way: `SplunkConfig.query` and `CarbonBlackConfig.query`
were `str | None`, the JSON Schema extras listed `query` as required, and the
deployers treated a missing query as "skip this rule". Authors opening the
Splunk or Carbon Black template saw `#query: |` commented out while the other
five platforms showed it live, and a splunk::2.x rule deployed with no search
string at all because nothing mapped its legacy `search` field.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from opentide.generation.pydantic_metaschema import build_platform_schema_source
from opentide.generation.pydantic_skeleton import render_model_template
from opentide.loading.platform_loader import load_splunk_config
from opentide.models.platform import (
    PLATFORM_CONFIG_MODELS,
    CarbonBlackConfig,
    SplunkConfig,
)
from opentide.models.platform_schema import platform_root_extras

#: Platforms whose configuration carries a query string at all. SentinelOne
#: expresses detection through `condition`, HarfangLab through sigma/yara, and
#: Elastic Security supports multiple rule types including machine_learning
#: where query is optional.
QUERY_PLATFORMS = [
    key
    for key, model in PLATFORM_CONFIG_MODELS.items()
    if "query" in model.model_fields and key != "elastic"
]


def test_the_query_platform_list_is_not_empty() -> None:
    assert len(QUERY_PLATFORMS) == 5


@pytest.mark.parametrize("key", QUERY_PLATFORMS)
def test_query_is_required_on_every_platform_that_has_one(key: str) -> None:
    field = PLATFORM_CONFIG_MODELS[key].model_fields["query"]
    assert field.is_required(), f"{key} declares query optional"


@pytest.mark.parametrize("key", sorted(PLATFORM_CONFIG_MODELS))
def test_field_requiredness_agrees_with_the_schema_extras(key: str) -> None:
    """Extras drive the published JSON Schema; the model drives loading.

    The extras' ``required`` used to replace the model's outright. Splunk's
    listed ``scheduling``, which the model leaves optional because a
    correlation search has nothing to schedule, so a rule written from the
    shipped template (which comments it out) was flagged. Elastic's left out
    ``type``, which the model requires.
    """
    model = PLATFORM_CONFIG_MODELS[key]
    published = build_platform_schema_source(model)["required"]
    for name, field in model.model_fields.items():
        published_name = field.alias or name
        assert (published_name in published) == field.is_required(), (
            f"{key}.{published_name}: schema and model disagree on whether it is required"
        )


@pytest.mark.parametrize("key", QUERY_PLATFORMS)
def test_templates_offer_query_uncommented(key: str) -> None:
    """The renderer follows FieldInfo, so authors see a live `query:` key."""
    rendered = render_model_template(PLATFORM_CONFIG_MODELS[key], indent=2)
    assert "\n  query: |" in rendered, f"{key} template comments out query"
    assert "#query:" not in rendered


@pytest.mark.parametrize("model", [SplunkConfig, CarbonBlackConfig])
def test_a_configuration_without_a_query_is_rejected(model: type) -> None:
    with pytest.raises(ValueError, match="query"):
        model(schema=f"{model.__name__}::3.0", status="STAGING")


@pytest.mark.parametrize("key", QUERY_PLATFORMS)
@pytest.mark.parametrize("blank", ["", "   ", "\n\t"])
def test_a_blank_query_is_rejected(key: str, blank: str) -> None:
    """Deployers skip a falsy query exactly as they skipped a missing one."""
    model = PLATFORM_CONFIG_MODELS[key]
    with pytest.raises(ValidationError) as caught:
        model.model_validate({"schema": f"{key}::1.0", "status": "STAGING", "query": blank})
    query_errors = [error for error in caught.value.errors() if error["loc"] == ("query",)]
    assert query_errors, f"{key} accepted a blank query"
    assert "query must not be empty" in query_errors[0]["msg"]


@pytest.mark.parametrize("key", sorted(PLATFORM_CONFIG_MODELS))
def test_schema_extras_require_no_field_the_model_leaves_optional(key: str) -> None:
    """The extras may repeat the model's required fields, never add to them.

    ``status`` and Splunk's ``scheduling`` were the last two exceptions. The
    deploy planner cannot proceed without a status, so the model now requires
    it; a Splunk correlation search has nothing to schedule, so the extras no
    longer require scheduling.
    """
    model = PLATFORM_CONFIG_MODELS[key]
    required = set(platform_root_extras(model).get("required", []))
    optional_in_model = {
        name
        for name in required
        if name in model.model_fields and not model.model_fields[name].is_required()
    }
    assert not optional_in_model, f"{key}: extras require {sorted(optional_in_model)}"


# --------------------------------------------------------------------------
# splunk::2.x keys are unknown keys
# --------------------------------------------------------------------------


SPLUNK_BLOCK = {
    "schema": "platform::splunk::1.0",
    "enabled": True,
    "name": "Splunk SPL Rule",
    "status": "STAGING",
    "query": "index=main | head 1",
}

#: Every splunk::2.x spelling, at its place in the block.
SPLUNK_2X_KEYS = [
    ("search", "index=main | head 1"),
    ("cron_schedule", "0 * * * *"),
    ("throttling", {"fields": ["host"], "duration": "1h"}),
    ("threshold", 3),
    ("notable", {"security_domain": "threat"}),
    ("risk", {"message": "risk message"}),
    ("email", {"to": ["soc@example.org"]}),
    ("scheduling", {"frequency": "1h"}),
    ("scheduling", {"cron": "0 * * * *"}),
    ("scheduling", {"custom_time": "09h15"}),
    ("scheduling", {"lookback": "2h"}),
]


@pytest.mark.parametrize(("key", "value"), SPLUNK_2X_KEYS)
def test_validation_refuses_a_splunk_2x_key(key: str, value: object) -> None:
    """A 2.x key is an unknown key, never moved onto the current layout."""
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SplunkConfig.model_validate({**SPLUNK_BLOCK, key: value})


@pytest.mark.parametrize(("key", "value"), SPLUNK_2X_KEYS)
def test_deploy_loading_refuses_a_splunk_2x_key(key: str, value: object) -> None:
    """``validate`` and ``deploy`` agree: the loader refuses what validation refuses."""
    with pytest.raises(ValidationError):
        load_splunk_config({**SPLUNK_BLOCK, key: value})


#: A custom alert action's parameters: what `advanced` exists for.
ADVANCED = {
    "action.misp_alert_create_event.param.title": "Canary token triggered",
    "action.misp_alert_create_event.param.distribution": 0,
    "action.misp_alert_create_event.param.publish_on_creation": True,
    "action.misp_alert_create_event.param.tags": None,
}


def test_advanced_is_part_of_the_splunk_layout() -> None:
    """0.21.0 refused `advanced` as a splunk::2.x key; it is a key of the current layout,
    and the only place a rule can set keys no other field sets."""
    config = SplunkConfig.model_validate({**SPLUNK_BLOCK, "advanced": ADVANCED})
    assert config.advanced == ADVANCED
    assert load_splunk_config({**SPLUNK_BLOCK, "advanced": ADVANCED}).advanced == ADVANCED


@pytest.mark.parametrize(
    "advanced",
    [{"action.x.param.y": ["a", "b"]}, {"action.x.param.y": {"a": 1}}, {" ": "value"}],
    ids=["list", "table", "blank-key"],
)
def test_advanced_refuses_what_savedsearches_conf_cannot_hold(advanced: dict) -> None:
    with pytest.raises(ValidationError):
        SplunkConfig.model_validate({**SPLUNK_BLOCK, "advanced": advanced})


def test_advanced_is_offered_by_the_editor_schema_and_hidden_from_the_template() -> None:
    properties = build_platform_schema_source(SplunkConfig)["properties"]
    assert "advanced" in properties
    assert "deprecated" not in properties["advanced"]
    assert "advanced" not in render_model_template(SplunkConfig)


def test_a_splunk_2x_search_without_a_query_is_no_query() -> None:
    block = {key: value for key, value in SPLUNK_BLOCK.items() if key != "query"}
    with pytest.raises(ValidationError) as caught:
        SplunkConfig.model_validate({**block, "search": "index=main"})
    locations = {error["loc"] for error in caught.value.errors()}
    assert ("query",) in locations and ("search",) in locations


@pytest.mark.parametrize("key", sorted(PLATFORM_CONFIG_MODELS))
def test_the_editor_schema_offers_exactly_what_validation_accepts_for_schema(key: str) -> None:
    """The extras were keyed by the field name, so the `schema` enum never applied."""
    model = PLATFORM_CONFIG_MODELS[key]
    prop = build_platform_schema_source(model)["properties"]["schema"]
    assert prop["enum"] == [model.schema_identifier(), None]
    assert prop["default"] == model.schema_identifier()
    block = _CORPUS_BLOCKS[key]
    model.model_validate({**block, "schema": model.schema_identifier()})
    model.model_validate({**block, "schema": None})
    with pytest.raises(ValidationError, match="unknown platform schema"):
        model.model_validate({**block, "schema": f"{key}::2.1"})


def _corpus_blocks() -> dict[str, dict]:
    import yaml
    from tests.corpus_support import TIDE_CORPUS_ROOT

    blocks: dict[str, dict] = {}
    for path in sorted((TIDE_CORPUS_ROOT / "Objects" / "Detection Rules").glob("*.yaml")):
        body = yaml.safe_load(path.read_text(encoding="utf-8"))
        for platform, block in (body.get("configurations") or {}).items():
            blocks.setdefault(platform, block)
    return blocks


_CORPUS_BLOCKS = _corpus_blocks()
