"""FieldInfo YAML skeleton renderer (issue #224–#226)."""

from __future__ import annotations

import inspect
import json
import re
from pathlib import Path
from typing import ClassVar, Literal

import pytest
import yaml

from opentide.generation.pydantic_metaschema import _CORE_ROOT_EXTRAS_BASE
from opentide.generation.pydantic_skeleton import (
    render_model_template,
    uncomment_optional_blocks,
    write_model_template,
)
from opentide.generation.pydantic_templates import generate_core_template
from opentide.models.base import TideField, TideModel, VocabField
from opentide.models.metadata import ObjectMetadata
from opentide.models.objective import DetectionObjective
from opentide.models.platform import RuleConfigurations, SentinelConfig
from opentide.models.response import RuleResponse
from opentide.models.rule import DetectionRule
from opentide.models.threat import ThreatVector

_FILE_KEY = re.compile(r"(?m)^[ ]*#?file:")
_NULL_TOKEN = re.compile(r"(?m)(?<![A-Za-z0-9_])null(?![A-Za-z0-9_])")


def _assert_no_null(text: str) -> None:
    assert "null" not in text
    assert _NULL_TOKEN.search(text) is None


def _assert_no_root_file_key(text: str) -> None:
    assert _FILE_KEY.search(text) is None


class _PlaceholderModel(TideModel):
    """Minimal model covering typed-placeholder branches."""

    __schema_identifier__: ClassVar[str] = "example::1.0"
    title: str
    created: str
    link: str | None = TideField(None, schema_extra={"format": "uri"})
    notes: str = TideField(schema_extra={"tide.template.multiline": True})
    count: int | None = None
    enabled: bool | None = None
    hidden: str | None = TideField(None, schema_extra={"tide.template.hide": True})
    path: Path | None = None
    kind: Literal["alpha", "beta"] = "alpha"
    tags: list[str] | None = None
    vocab: str = VocabField(True)
    email: str | None = TideField(None, schema_extra={"format": "email"})


class _NestedOptional(TideModel):
    uuid: str
    name: str


class _ParentModel(TideModel):
    required_child: _NestedOptional
    optional_child: _NestedOptional | None = None


class _NestedWithOptional(TideModel):
    uuid: str
    note: str | None = None


class _StackModel(TideModel):
    wrapper: _NestedWithOptional | None = None


def test_required_only_metadata_tlp_is_scalar() -> None:
    text = render_model_template(ObjectMetadata, required_only=True)
    loaded = yaml.safe_load(text)
    _assert_no_null(text)
    assert not isinstance(loaded["tlp"], dict)
    assert "organisation" not in loaded
    assert loaded["schema"] is None or loaded["schema"] == ""
    assert "uuid" in loaded
    assert "author" not in loaded


def test_object_metadata_schema_alias_and_dates() -> None:
    text = render_model_template(ObjectMetadata, schema_id="threat::1.0")
    assert "schema: threat::1.0" in text
    assert "created: YYYY-MM-DD" in text
    assert "modified: YYYY-MM-DD" in text
    assert "schema_id:" not in text
    assert "#organisation:" in text
    assert re.search(r"(?m)^  #uuid:", text)
    assert re.search(r"(?m)^  #name:", text)
    assert re.search(r"(?m)^#  uuid:", text) is None
    loaded = yaml.safe_load(text)
    assert loaded["tlp"] in (None, "")
    assert "organisation" not in loaded
    assert loaded["uuid"] in (None, "")
    assert "uuid" in loaded


def test_optional_organisation_uncomment_is_valid_yaml() -> None:
    text = render_model_template(ObjectMetadata)
    recovered = uncomment_optional_blocks(text)
    loaded = yaml.safe_load(recovered)
    assert loaded["organisation"]["uuid"] in (None, "")
    assert loaded["organisation"]["name"] in (None, "")


def test_threat_vector_nested_body_and_commented_optionals() -> None:
    text = render_model_template(ThreatVector, schema_id="threat::1.0")
    _assert_no_null(text)
    _assert_no_root_file_key(text)
    assert "threat:" in text
    after_threat = text.split("\nthreat:", 1)[1]
    assert "description: |" in after_threat
    assert "att&ck:" in after_threat
    assert "surface:" in after_threat
    assert "#actors:" in after_threat
    assert "#killchain:" in after_threat
    assert "#chaining:" in after_threat
    loaded = yaml.safe_load(text)
    assert "actors" not in loaded["threat"]
    assert loaded["metadata"]["schema"] == "threat::1.0"


def test_objective_signals_and_composition() -> None:
    text = render_model_template(DetectionObjective, schema_id="objective::1.0")
    assert "composition:" in text
    assert "strategy:" in text
    assert "signals:" in text
    after_data = text.split("data:", 1)[1].split("methodology:", 1)[0]
    assert "availability:" in after_data
    assert "requirements:" in after_data
    assert "#availability:" not in after_data
    assert "#logsources:" in after_data
    loaded = yaml.safe_load(text)
    signal = loaded["objective"]["signals"][0]
    assert "name" in signal
    assert "uuid" in signal
    assert "availability" in signal["data"]
    assert "#effort: 3" in text


def test_rule_response_and_hidden_file() -> None:
    text = render_model_template(DetectionRule, schema_id="rule::1.0")
    _assert_no_null(text)
    _assert_no_root_file_key(text)
    assert "platforms:" not in text
    assert "#platforms:" not in text
    assert "response:" in text
    assert "alert_severity: Informational" in text
    assert "#procedure:" in text
    loaded = yaml.safe_load(text)
    response = loaded.get("response") or {}
    assert "analysis" not in response
    assert "procedure" not in response


def test_rule_configurations_commented_platform_stubs_not_empty_map() -> None:
    text = render_model_template(DetectionRule, schema_id="rule::1.0")
    assert "configurations: {}" not in text
    assert "#sentinel:" in text
    assert "query: |" in text
    assert "schema: rule::1.0" in text
    assert "schema: platform::sentinel::1.0" in text
    assert "schema: platform::splunk::1.0" in text
    loaded = yaml.safe_load(text)
    configs = loaded.get("configurations") or {}
    assert "sentinel" not in configs
    recovered = uncomment_optional_blocks(text)
    full = yaml.safe_load(recovered)
    sentinel = (full.get("configurations") or {}).get("sentinel", {})
    assert "query" in sentinel
    assert sentinel.get("schema") == "platform::sentinel::1.0"


def test_rule_response_model_procedure_commented() -> None:
    text = render_model_template(RuleResponse)
    _assert_no_null(text)
    assert "#procedure:" in text
    assert re.search(r"(?m)^  #analysis: \|", text)
    assert re.search(r"(?m)^  #searches:", text)
    assert re.search(r"(?m)^  ##searches:", text) is None
    loaded = yaml.safe_load(text)
    assert loaded is None
    recovered = uncomment_optional_blocks(text)
    full = yaml.safe_load(recovered)
    assert full["alert_severity"] == "Informational"
    assert "analysis" in full["procedure"]


def test_sentinel_config_from_model_fields() -> None:
    text = render_model_template(SentinelConfig)
    _assert_no_null(text)
    assert "query: |" in text
    assert "scheduling:" in text
    assert "alert:" in text
    assert "#enabled: false" in text
    assert "schema: platform::sentinel::1.0" in text
    loaded = yaml.safe_load(text)
    assert "query" in loaded
    assert loaded["query"].strip() == "..."
    assert loaded["schema"] == "platform::sentinel::1.0"


def test_rule_configurations_walks_all_platform_slots() -> None:
    text = render_model_template(RuleConfigurations)
    for key in (
        "sentinel",
        "defender_for_endpoint",
        "splunk",
        "sentinel_one",
        "crowdstrike",
        "harfanglab",
        "carbon_black_cloud",
    ):
        assert f"#{key}:" in text


def test_write_model_template_indent(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "sentinel.yaml"
    write_model_template(path, SentinelConfig, indent=2)
    text = path.read_text(encoding="utf-8")
    assert text.startswith("  ")
    assert "  query: |" in text
    assert "schema: platform::sentinel::1.0" in text


def test_generate_core_templates_match_renderer(tmp_path: Path) -> None:
    for key, model, schema in (
        ("threat", ThreatVector, "threat::1.0"),
        ("objective", DetectionObjective, "objective::1.0"),
        ("rule", DetectionRule, "rule::1.0"),
    ):
        path = tmp_path / f"{key}.yaml"
        generate_core_template(key, path)
        assert path.read_text(encoding="utf-8") == render_model_template(model, schema_id=schema)
        _assert_no_null(path.read_text(encoding="utf-8"))


def test_typed_placeholders_on_minimal_model() -> None:
    text = render_model_template(_PlaceholderModel)
    _assert_no_null(text)
    assert "title: " in text
    assert "created: YYYY-MM-DD" in text
    assert "#link: https://" in text
    assert "notes: |" in text
    assert "  ..." in text
    assert "#count: 3" in text
    assert "#enabled: false" in text
    assert "hidden:" not in text
    assert "path:" not in text
    assert "#kind: alpha" in text
    assert "#tags:" in text
    assert "vocab: " in text
    assert "#email: author@domain.com" in text
    assert "schema: example::1.0" not in text


def test_nested_optional_uncomment_roundtrip() -> None:
    text = render_model_template(_ParentModel)
    assert "required_child:" in text
    assert "  uuid:" in text
    assert "#optional_child:" in text
    assert re.search(r"(?m)^  #uuid:", text)
    assert re.search(r"(?m)^#  uuid:", text) is None
    recovered = uncomment_optional_blocks(text)
    loaded = yaml.safe_load(recovered)
    assert loaded["required_child"]["uuid"] in (None, "")
    assert loaded["optional_child"]["name"] in (None, "")


def test_optional_subtree_is_commented_once() -> None:
    """Nested optionals stay live YAML; ``#`` hugs each key once."""
    text = render_model_template(_StackModel)
    assert "#wrapper:" in text
    assert re.search(r"(?m)^  #uuid:", text)
    assert re.search(r"(?m)^  #note:", text)
    assert re.search(r"(?m)^  ##note:", text) is None
    assert re.search(r"(?m)^[ ]*#[ ]+#", text) is None
    recovered = uncomment_optional_blocks(text)
    loaded = yaml.safe_load(recovered)
    assert loaded["wrapper"]["uuid"] in (None, "")
    assert "note" in loaded["wrapper"]


def test_core_templates_do_not_stack_comment_markers() -> None:
    stacked = re.compile(r"(?m)^[ ]*#[ ]+#")
    for model, schema in (
        (ThreatVector, "threat::1.0"),
        (DetectionObjective, "objective::1.0"),
        (DetectionRule, "rule::1.0"),
        (SentinelConfig, None),
    ):
        kwargs = {"schema_id": schema} if schema else {}
        text = render_model_template(model, **kwargs)
        match = stacked.search(text)
        assert match is None, f"{model.__name__}: {match.group(0)!r}"


def test_optional_comments_hug_field_names() -> None:
    """``#`` sits against the key, not at the parent indent with padding."""
    text = render_model_template(ThreatVector, schema_id="threat::1.0")
    assert re.search(r"(?m)^#references:", text)
    assert re.search(r"(?m)^  #public:", text)
    assert re.search(r"(?m)^    #1:", text)
    assert re.search(r"(?m)^  #internal:", text)
    assert re.search(r"(?m)^    #key:", text)
    assert re.search(r"(?m)^  #reports:", text)
    assert re.search(r"(?m)^    #-", text)
    assert re.search(r"(?m)^#  public:", text) is None
    rule = render_model_template(DetectionRule, schema_id="rule::1.0")
    assert re.search(r"(?m)^  #sentinel:", rule)
    assert re.search(r"(?m)^    #enabled:", rule)
    assert re.search(r"(?m)^  #  enabled:", rule) is None


def test_commented_optional_block_is_contiguous() -> None:
    text = render_model_template(DetectionRule, schema_id="rule::1.0")
    sentinel = text.split("#sentinel:", 1)[1].split("#defender_for_endpoint:", 1)[0]
    live_lines = [
        line for line in sentinel.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]
    assert live_lines == []


def test_skeleton_module_does_not_yaml_dump_hash_keys() -> None:
    from opentide.generation import pydantic_skeleton as skeleton

    source = Path(inspect.getfile(skeleton)).read_text(encoding="utf-8")
    assert "yaml.dump" not in source
    assert "gen_template" not in source


def test_template_engine_no_schema_walker() -> None:
    from opentide.generation import template_engine

    assert not hasattr(template_engine, "gen_template")
    assert not hasattr(template_engine, "get_required")
    assert not hasattr(template_engine, "definition_handler")
    assert not hasattr(template_engine, "emit_template_file")


def test_core_root_extras_have_no_template_keys() -> None:
    blob = json.dumps(_CORE_ROOT_EXTRAS_BASE)
    assert "tide.template." not in blob


class _DictModels(TideModel):
    items: dict[str, _NestedOptional]
    counts: dict[str, list[int]]
    scores: list[int]


class _UnionBody(TideModel):
    body: str | _NestedOptional


class _ScalarEdges(TideModel):
    ratio: float | None = None
    amount: float = 1.5
    tagged: str = "yes"
    numeric: str = "10"
    quoted: str = "hello world"
    mapping_default: dict[str, str] = {"a": "b"}  # type: ignore[assignment]
    list_default: list[str] = ["x"]  # type: ignore[assignment]
    vocab_default: str = VocabField(True, default="low")
    optional_forced_off: str = TideField(schema_extra={"tide.template.required": False})
    numbered: int = 7
    flag: bool = True
    extra: str | None = TideField(None, schema_extra={"format": "number"})


def test_dict_of_models_and_list_of_ints() -> None:
    text = render_model_template(_DictModels)
    assert "items:" in text
    assert "  key:" in text
    assert "    uuid:" in text
    assert "counts:" in text
    assert "    - " in text
    assert "scores:" in text
    assert "- 3" in text or "- 3" in text.replace("\n", " ")


def test_union_prefers_nested_model() -> None:
    text = render_model_template(_UnionBody)
    assert "body:" in text
    assert "  uuid:" in text


def test_scalar_edge_placeholders() -> None:
    text = render_model_template(_ScalarEdges)
    assert "#ratio: 3" in text
    assert "#amount: 1.5" in text
    assert '#tagged: "yes"' in text
    assert '#numeric: "10"' in text
    assert '#quoted: "hello world"' in text
    assert "#vocab_default: low" in text
    assert "#numbered: 7" in text
    assert "#flag: true" in text
    assert "#extra: 3" in text
    assert "#optional_forced_off:" in text
    loaded = yaml.safe_load(text)
    assert loaded is None or "optional_forced_off" not in loaded


def test_comment_and_helper_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    from typing import Annotated, Any

    from opentide.generation import pydantic_skeleton as sk

    assert sk._render_model(ObjectMetadata, indent=0, options=sk.RenderOptions(), depth=99) == []
    assert sk._list_item_lines([], 2) == ["  - "]
    assert sk._comment_hug_keys(["x"], 2) == ["#x"]
    assert sk._comment_hug_keys(["  public:", "    1: "], 0) == ["  #public:", "    #1: "]
    assert sk._comment_hug_keys([""], 2) == ["  #"]
    assert sk._comment_hug_keys(["  #already"], 0) == ["  #already"]
    assert sk._format_scalar({"a": 1}) == ""
    assert sk._format_scalar((1, 2)) == ""
    assert sk._format_scalar(3) == "3"
    assert sk._format_scalar(1.5) == "1.5"
    assert sk._format_string("") == ""
    assert sk._format_string("true") == '"true"'
    assert sk._pick_union([]) is str
    assert sk._pick_union([Any, Any]) is Any
    assert sk._tide_model_type(Annotated[_NestedOptional, "x"]) is _NestedOptional
    assert sk._tide_model_type(object()) is None
    assert sk._is_path_type(object()) is False
    assert sk._literal_values(str) is None

    field = ObjectMetadata.model_fields["uuid"]
    fake = type(field)(annotation=None)
    assert sk._render_field("gone", fake, indent=0, options=sk.RenderOptions(), depth=0) == []

    assert sk._scalar_placeholder("n", int | str, {}, sk.RenderOptions()) == "3"

    real_issubclass = __import__("builtins").issubclass

    def _boom(cls: type, parent: type) -> bool:
        if cls is int:
            raise TypeError("not a class")
        return real_issubclass(cls, parent)

    monkeypatch.setattr("builtins.issubclass", _boom)
    assert sk._tide_model_type(int) is None
    assert sk._is_path_type(int) is False

    union_text = sk._scalar_placeholder("n", int | str, {}, sk.RenderOptions())
    assert union_text == "3"

    real_issubclass = __import__("builtins").issubclass

    def _boom(cls: type, parent: type) -> bool:
        if cls is int:
            raise TypeError("not a class")
        return real_issubclass(cls, parent)

    monkeypatch = __import__("pytest").MonkeyPatch()
    monkeypatch.setattr("builtins.issubclass", _boom)
    try:
        assert sk._tide_model_type(int) is None
        assert sk._is_path_type(int) is False
    finally:
        monkeypatch.undo()
