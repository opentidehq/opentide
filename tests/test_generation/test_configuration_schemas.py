"""Configuration JSON Schema export: one schema per file kind, plus a router by file name.

`tests/fixtures/configuration_schemas/` holds the exported documents. A model
change that alters a schema fails `test_export_matches_fixture`; regenerate
the fixtures with

    uv run python -m opentide.generation.configuration_schemas \\
        tests/fixtures/configuration_schemas
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from opentide.generation.configuration_schemas import (
    ROUTER_NAME,
    build_configuration_router,
    configuration_schema_name,
    export_configuration_schemas,
    generate_configuration_schema,
    generate_configuration_schemas,
    main,
    render_schema,
)
from opentide.models.configuration import (
    configuration_file_key,
    configuration_files,
    configuration_model_for,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "configuration_schemas"
_DOCUMENTS = generate_configuration_schemas()


def _undescribed(node: Any, where: str, found: list[str]) -> None:
    """Every property of every object schema, and every `$defs` entry, has a description."""
    if isinstance(node, dict):
        properties = node.get("properties")
        if isinstance(properties, dict):
            for key, value in properties.items():
                if not (isinstance(value, dict) and value.get("description")):
                    found.append(f"{where}.properties.{key}")
        for name, definition in (node.get("$defs") or {}).items():
            if isinstance(definition, dict) and not definition.get("description"):
                found.append(f"{where}.$defs.{name}")
        for key, value in node.items():
            _undescribed(value, f"{where}/{key}", found)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            _undescribed(item, f"{where}[{index}]", found)


@pytest.mark.parametrize("name", sorted(_DOCUMENTS))
def test_export_matches_fixture(name: str) -> None:
    fixture = FIXTURES / name
    assert fixture.is_file(), f"missing fixture {name}; regenerate (see module docstring)"
    assert render_schema(_DOCUMENTS[name]) == fixture.read_text(encoding="utf-8")


def test_no_stale_fixture() -> None:
    assert sorted(path.name for path in FIXTURES.glob("*.json")) == sorted(_DOCUMENTS)


@pytest.mark.parametrize("name", sorted(set(_DOCUMENTS) - {ROUTER_NAME}))
def test_every_field_has_a_description(name: str) -> None:
    found: list[str] = []
    _undescribed(_DOCUMENTS[name], name, found)
    assert found == []


def test_description_check_catches_an_undocumented_field() -> None:
    from pydantic import BaseModel, Field

    class Example(BaseModel):
        """Documented model."""

        documented: str = Field(description="Has one.")
        bare: str

    found: list[str] = []
    _undescribed(Example.model_json_schema(), "example", found)
    assert found == ["example.properties.bare"]


def test_export_is_model_json_schema() -> None:
    for key, model in configuration_files().items():
        schema = generate_configuration_schema(key)
        raw = model.model_json_schema()
        assert schema["properties"].keys() == raw["properties"].keys()
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_router_names_every_file() -> None:
    files = build_configuration_router()["files"]
    for key in (
        "paths.toml",
        "global.toml",
        "deployment.toml",
        "schema.toml",
        "visibility.toml",
        "documentation.toml",
        "sharing.toml",
        "platforms/sentinel.toml",
        "platforms/splunk.toml",
        "platforms/*.toml",
    ):
        assert files[key]["schema"] in _DOCUMENTS
    assert files["global.toml"]["schema"] == files["paths.toml"]["schema"]
    assert files["sharing.toml"]["merge"] == "by-name"
    assert files["sharing.toml"]["connectors"] == {"misp": "sharing::misp::1.0"}
    assert files["visibility.toml"]["schema_id"] == "visibility::1.0"
    assert "schema_id" not in files["sharing.toml"]


@pytest.mark.parametrize(
    ("path", "key"),
    [
        ("deployment.toml", "deployment.toml"),
        ("/repo/.opentide/configurations/sharing.toml", "sharing.toml"),
        (".opentide/configurations/platforms/elastic.toml", "platforms/elastic.toml"),
        ("platforms/acme.toml", "platforms/*.toml"),
        ("C:\\repo\\.opentide\\configurations\\platforms\\splunk.toml", "platforms/splunk.toml"),
        ("resources.toml", None),
        ("deployment.yaml", None),
    ],
)
def test_file_routing(path: str, key: str | None) -> None:
    assert configuration_file_key(path) == key
    assert (configuration_model_for(path) is None) is (key is None)


def test_schema_names() -> None:
    assert configuration_schema_name("platforms/sentinel.toml") == "platforms.sentinel.schema.json"
    assert configuration_schema_name("platforms/*.toml") == "platforms.schema.json"
    assert configuration_schema_name("global.toml") == "paths.schema.json"


# --- Shape the language server relies on ----------------------------------------------


def _def(schema: dict[str, Any], name: str) -> dict[str, Any]:
    return schema["$defs"][name]


def test_sharing_schema_shape() -> None:
    schema = _DOCUMENTS["sharing.schema.json"]
    assert schema.get("additionalProperties") is not False
    assert "sharing::1.0" not in json.dumps(schema)
    misp = _def(schema, "MispIntegration")
    assert misp["x-opentide-schema-id"] == "sharing::misp::1.0"
    assert misp["additionalProperties"] is False
    assert misp["required"] == ["name", "url", "api_key", "max_tlp"]
    assert sorted(misp["properties"]) == sorted(
        [
            "name",
            "enabled",
            "url",
            "api_key",
            "max_tlp",
            "object_types",
            "rule_statuses",
            "organisation_uuid",
            "publish",
            "verify_ssl",
        ]
    )
    assert "distribution" not in misp["properties"]
    max_tlp = misp["properties"]["max_tlp"]
    assert max_tlp["enum"] == ["clear", "green", "amber", "amber+strict", "red"]
    assert "default" not in max_tlp
    assert "pattern" not in misp["properties"]["api_key"]
    assert misp["properties"]["rule_statuses"]["items"]["type"] == "string"
    assert misp["properties"]["object_types"]["items"]["enum"] == ["threat", "objective", "rule"]


def test_sharing_schema_validates_documents() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    validator = jsonschema.Draft202012Validator(_DOCUMENTS["sharing.schema.json"])
    fixtures = Path(__file__).resolve().parents[1] / "fixtures" / "specifications" / "sharing"
    merged = tomllib.loads((fixtures / "valid" / "merged.toml").read_text(encoding="utf-8"))
    assert list(validator.iter_errors(merged)) == []
    assert list(validator.iter_errors({"opencti": [{"name": "sector"}]})) == []
    assert list(validator.iter_errors({"misp": [{"name": "m", "distribution": "x"}]}))
    assert list(validator.iter_errors({"targets": {"misp": {}}}))


def test_enums_for_completion() -> None:
    deployment = _DOCUMENTS["deployment.schema.json"]
    strategy = _def(deployment, "DeploymentStatusEntry")["properties"]["strategy"]
    assert strategy["enum"] == [
        "INERT",
        "RELEASE",
        "PREVIEW",
        "DISABLEMENT",
        "DELETION",
        "UNIVERSAL",
    ]
    tenant = _def(_DOCUMENTS["platforms.sentinel.schema.json"], "SentinelTenant")
    assert {"enum": ["PREVIEW", "RELEASE"], "type": "string"} in tenant["properties"]["strategies"][
        "anyOf"
    ]
    documentation = _DOCUMENTS["documentation.schema.json"]
    assert _def(documentation, "DocumentFlavor")["enum"] == [
        "github",
        "gitlab",
        "azure_devops",
        "generic",
    ]
    assert documentation["properties"]["scope"]["items"]["enum"] == ["threat", "objective", "rule"]


def test_tlp_enum_matches_the_bundled_vocabulary() -> None:
    from opentide.core.root import get_data_root
    from opentide.sharing.constants import TLP_ORDER

    vocab = tomllib.loads(
        (get_data_root() / "vocabulary" / "tlp.vocab.toml").read_text(encoding="utf-8")
    )
    names = [key["name"] for key in vocab["keys"]]
    misp = _def(_DOCUMENTS["sharing.schema.json"], "MispIntegration")
    assert misp["properties"]["max_tlp"]["enum"] == names == list(TLP_ORDER)


def test_unknown_keys_are_rejected_except_open_tables() -> None:
    schema = _DOCUMENTS["schema.schema.json"]
    assert schema["additionalProperties"] is False
    assert _def(schema, "VocabularyExtensions")["additionalProperties"] is True
    for name in ("deployment.schema.json", "documentation.schema.json", "paths.schema.json"):
        assert _DOCUMENTS[name]["additionalProperties"] is False


def test_no_framework_keywords_leak() -> None:
    assert "tide." not in json.dumps(_DOCUMENTS["visibility.schema.json"])


def test_export_writes_every_document(tmp_path: Path) -> None:
    written = export_configuration_schemas(tmp_path / "out")
    assert sorted(path.name for path in written) == sorted(_DOCUMENTS)
    router = json.loads((tmp_path / "out" / ROUTER_NAME).read_text(encoding="utf-8"))
    assert router == _DOCUMENTS[ROUTER_NAME]


def test_main(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(tmp_path)]) == 0
    assert ROUTER_NAME in capsys.readouterr().out
    assert main([]) == 2
