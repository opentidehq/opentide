"""`response.responders` as a configuration enum.

Not a vocabulary: the alert handling team is per-organisation, so the allowed
values come from `[[responders]]` in `deployment.toml`.

The load-bearing case is :func:`test_no_configured_responders_is_unconstrained`.
A validated field bound to an empty shipped list is precisely what made the
old `responders` vocabulary unclearable by any instance (#507), so declaring
none MUST leave the field free rather than rejecting everything.
"""

from __future__ import annotations

from typing import Any

import pytest

from opentide.validation.field_vocab import (
    CONFIG_ENUM_KEYWORDS,
    CONFIG_ENUM_RESOLVERS,
    _validate_config_enum_value,
)

KEYWORD = "tide.config.responders"


@pytest.fixture(autouse=True)
def _no_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default every test to 'nothing configured'.

    The validator falls back to reading configuration when the node carries
    no `enum`, and a unit test has no workspace. Tests that care about the
    configured set override this explicitly.
    """
    monkeypatch.setitem(CONFIG_ENUM_RESOLVERS, KEYWORD, lambda: [])


def _schema(allowed: list[str] | None, *, as_array: bool = False) -> dict[str, Any]:
    """Build the metaschema node the generation pipeline would write."""
    node: dict[str, Any] = {KEYWORD: True, "type": "array" if as_array else "string"}
    if allowed is not None:
        if as_array:
            node["items"] = {"enum": allowed, "uniqueItems": True}
        else:
            node["enum"] = allowed
    return node


def _check(value: Any, schema: dict[str, Any]) -> list:
    return _validate_config_enum_value(
        value,
        schema,
        field_path=("response", "responders"),
        object_uuid="u",
        object_type="rule",
    )


def test_keyword_is_registered() -> None:
    assert KEYWORD in CONFIG_ENUM_KEYWORDS
    assert KEYWORD in CONFIG_ENUM_RESOLVERS


def test_configured_value_is_accepted() -> None:
    assert _check("CSIRC", _schema(["CSIRC", "CATCH"])) == []


def test_unconfigured_value_is_rejected() -> None:
    issues = _check("NOPE", _schema(["CSIRC", "CATCH"]))
    assert len(issues) == 1
    assert issues[0].code == "config_enum_unknown"
    assert issues[0].severity == "error"
    assert issues[0].field_path == ("response", "responders")


def test_the_error_names_the_block_to_edit_and_the_valid_values() -> None:
    """The remedy is the instance's own configuration, so say so.

    A vocabulary finding is fixed upstream; this one is fixed by the reader,
    and the message has to make that difference obvious.
    """
    message = _check("NOPE", _schema(["CSIRC", "CATCH"]))[0].message
    assert "[[responders]]" in message
    assert "CSIRC" in message and "CATCH" in message
    assert "deployment configuration" in message


def test_no_configured_responders_is_unconstrained() -> None:
    """Declaring no teams must not reject every value.

    This is the #507 regression guard. A shipped empty list bound to a
    validated field is unsatisfiable by any instance, because configuration
    is the only place teams can be declared.
    """
    assert _check("ANYTHING", _schema(None)) == []
    assert _check("ANYTHING", _schema([])) == []


def test_unset_value_is_always_accepted() -> None:
    assert _check(None, _schema(["CSIRC"])) == []


def test_non_string_values_are_left_to_type_validation() -> None:
    assert _check(7, _schema(["CSIRC"])) == []


def test_array_form_validates_each_item() -> None:
    schema = _schema(["CSIRC", "CATCH"], as_array=True)
    assert _check(["CSIRC", "CATCH"], schema) == []
    issues = _check(["CSIRC", "NOPE"], schema)
    assert len(issues) == 1
    assert "NOPE" in issues[0].message


# --------------------------------------------------------------------------
# The generated enum is the single source both consumers read
# --------------------------------------------------------------------------


def test_an_enum_on_the_node_takes_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    """An enriched schema is validated against exactly what it advertises."""
    monkeypatch.setitem(CONFIG_ENUM_RESOLVERS, KEYWORD, lambda: ["CSIRC", "CATCH"])
    issues = _check("CSIRC", _schema(["ONLY_THIS"]))
    assert len(issues) == 1, "the node's own enum must win over configuration"
    assert "ONLY_THIS" in issues[0].message


def test_configuration_is_read_when_the_node_has_no_enum(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The path `validate` actually takes.

    Validation walks the UN-enriched metaschema: it carries the keyword but
    no `enum`, because the enum is written later during schema generation.
    So the allowed set has to come from configuration here, through the same
    function the generation pipeline reads.
    """
    monkeypatch.setitem(CONFIG_ENUM_RESOLVERS, KEYWORD, lambda: ["CSIRC", "CATCH"])
    unenriched = {KEYWORD: True, "anyOf": [{"type": "string"}, {"type": "null"}]}

    assert _check("CATCH", unenriched) == []
    issues = _check("NOT_A_TEAM", unenriched)
    assert len(issues) == 1
    assert issues[0].code == "config_enum_unknown"
    assert "CSIRC, CATCH" in issues[0].message


def test_resolver_emits_nothing_when_none_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    """No configured teams means no `enum` key is written at all."""
    from opentide.generation import schema_pipeline

    monkeypatch.setattr(schema_pipeline, "_ensure_runtime_context", lambda: None)

    class _Deployment:
        responders: list = []

    class _Configurations:
        Deployment = _Deployment

    class _OpenTide:
        Configurations = _Configurations

    monkeypatch.setattr(schema_pipeline, "OpenTide", _OpenTide)
    values, descriptions = schema_pipeline.VocabularyResolver.Responders().resolve()
    assert values == []
    assert descriptions == []


def test_resolver_reads_names_and_descriptions(monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.generation import schema_pipeline
    from opentide.models.system_config import DeploymentResponder

    monkeypatch.setattr(schema_pipeline, "_ensure_runtime_context", lambda: None)

    class _Deployment:
        responders = [
            DeploymentResponder(name="CSIRC", description="First line"),
            DeploymentResponder(name="CATCH", description="Escalation"),
        ]

    class _Configurations:
        Deployment = _Deployment

    class _OpenTide:
        Configurations = _Configurations

    monkeypatch.setattr(schema_pipeline, "OpenTide", _OpenTide)
    values, descriptions = schema_pipeline.VocabularyResolver.Responders().resolve()
    assert values == ["CSIRC", "CATCH"]
    assert descriptions == ["First line", "Escalation"]


def test_shipped_template_declares_no_responders() -> None:
    """The shipped default must not constrain anyone.

    Reads the template rather than restating it, so re-introducing a
    populated default fails here. Absent and empty both mean unconstrained.
    """
    from opentide.core.io import load_toml
    from opentide.core.root import get_data_root

    config = load_toml(get_data_root() / "configurations" / "deployment.toml")
    assert not config.get("responders"), (
        "the shipped deployment template must declare no responders, or every "
        "authored value becomes invalid on a fresh install (#507)"
    )
    assert config.get("default_responders") == ""


def test_template_survives_a_user_declaring_responders(tmp_path: Any) -> None:
    """`default_responders` must still apply after teams are declared.

    The hazard is TOML's, not the reader's: a root-level key written below an
    array-of-tables belongs to that table. An early draft of this template
    put `default_responders` under the `[[responders]]` block, and it read as
    empty while visibly set to a team name -- the file still *looks* right,
    so only a parse catches it.

    This appends the block the template tells a user to uncomment, then
    checks the root key survived. Parsed through the project's own loader,
    which carries the `tomli` fallback for the 3.10 floor.
    """
    from opentide.core.io import load_toml
    from opentide.core.root import get_data_root

    text = (get_data_root() / "configurations" / "deployment.toml").read_text(encoding="utf-8")
    declared = text.replace('default_responders = ""', 'default_responders = "CSIRC"', 1) + (
        '\n[[responders]]\nname = "CSIRC"\ndescription = "First line"\n'
    )
    probe = tmp_path / "deployment.toml"
    probe.write_text(declared, encoding="utf-8")
    config = load_toml(probe)

    assert config.get("default_responders") == "CSIRC", (
        "default_responders was folded into a table; every root-level key must "
        "appear above the first [[...]] block in the template"
    )
    assert [entry["name"] for entry in config["responders"]] == ["CSIRC"]


def test_the_model_declares_the_configuration_keyword() -> None:
    """The field must carry the keyword, or no enum is ever generated."""
    from opentide.models.response import RuleResponse

    extra = RuleResponse.model_fields["responders"].json_schema_extra
    assert isinstance(extra, dict)
    assert extra.get(KEYWORD) is True
    assert "tide.vocab" not in extra, "responders is a configuration enum, not a vocabulary"
