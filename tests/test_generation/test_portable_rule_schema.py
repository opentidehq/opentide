"""The editor rule schema accepts a block for a platform the workspace has not enabled (#410).

Regression lock for #411 and #412. ``recomposition`` once dropped disabled
platforms from ``configurations``, and ``tenants`` was an enum of local tenant
names, so VS Code rejected a rule imported from another repository. The block
is legal: ``validate`` warns on it (#413) and deploy skips it (#414).
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from opentide.generation.pydantic_schemas import generate_schema_for_identifier
from opentide.loading.object_loader import load_object

_SPLUNK_BLOCK = {
    "enabled": True,
    "name": "Imported Splunk Rule",
    "status": "PRODUCTION",
    "query": "index=main | head 1",
    "tenants": ["other-repo"],
}


@pytest.fixture(scope="module")
def sentinel_only(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """The rule schema generated in a corpus where only Sentinel is enabled, and a rule."""
    from tests.corpus_support import clear_runtime_caches, materialise_corpus

    from opentide.platforms.enabled import enabled_systems

    repo = materialise_corpus(tmp_path_factory.mktemp("portable") / "corpus")
    for config in (repo / ".opentide" / "configurations" / "systems").glob("*.toml"):
        if config.stem != "sentinel":
            text = config.read_text(encoding="utf-8")
            config.write_text(text.replace("enabled = true", "enabled = false", 1), "utf-8")
    patch = pytest.MonkeyPatch()
    patch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    patch.setenv("OPENTIDE_TIDE_WORKSPACE", str(repo))
    clear_runtime_caches()
    try:
        enabled = enabled_systems()
        schema = generate_schema_for_identifier("rule::1.0")
    finally:
        patch.undo()
        clear_runtime_caches()
    path = next((repo / "objects" / "rules").glob("rule-0001-*.yaml"))
    # JSON round trip turns YAML dates into the strings an editor sees.
    rule = json.loads(json.dumps(yaml.safe_load(path.read_text(encoding="utf-8")), default=str))
    return {"enabled": enabled, "schema": schema, "rule": rule}


def _errors(schema: dict[str, Any], body: dict[str, Any]) -> list[str]:
    """Every message, including those under ``anyOf`` (``configurations`` is nullable)."""
    pending = list(Draft202012Validator(schema).iter_errors(body))
    messages: list[str] = []
    while pending:
        error = pending.pop()
        messages.append(error.message)
        pending.extend(error.context or ())
    return messages


def _with_block(rule: dict[str, Any], key: str) -> dict[str, Any]:
    body = copy.deepcopy(rule)
    body["configurations"][key] = dict(_SPLUNK_BLOCK)
    return body


def test_workspace_enables_only_sentinel(sentinel_only: dict[str, Any]) -> None:
    assert sentinel_only["enabled"] == ["sentinel"]


def test_schema_accepts_a_disabled_platform_block_for_another_repos_tenant(
    sentinel_only: dict[str, Any],
) -> None:
    body = _with_block(sentinel_only["rule"], "splunk")
    load_object(body)
    assert _errors(sentinel_only["schema"], body) == []


def test_schema_still_rejects_an_unknown_platform_key(sentinel_only: dict[str, Any]) -> None:
    errors = _errors(sentinel_only["schema"], _with_block(sentinel_only["rule"], "splnk"))
    assert any("splnk" in message for message in errors)


def test_schema_still_checks_the_disabled_platform_block(sentinel_only: dict[str, Any]) -> None:
    body = _with_block(sentinel_only["rule"], "splunk")
    body["configurations"]["splunk"]["unknown_key"] = True
    del body["configurations"]["splunk"]["query"]
    errors = _errors(sentinel_only["schema"], body)
    assert any("unknown_key" in message for message in errors)
    assert any("'query' is a required property" in message for message in errors)
