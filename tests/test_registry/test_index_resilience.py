"""Registry indexing resilience and validation overview behaviour."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
import yaml

from opentide.core.index_manager import IndexManager
from opentide.core.registry import OpenTide
from opentide.registry.builder import build_registry
from opentide.validation.checks.kinds import ValidateCheck
from opentide.validation.session import run_validation


@pytest.fixture(autouse=True)
def _reset_index_cache() -> None:
    IndexManager._cache = None
    OpenTide._initialised = False
    OpenTide._index = None
    yield
    IndexManager._cache = None
    OpenTide._initialised = False
    OpenTide._index = None


def _minimal_rule(uuid: str, *, name: str = "broken-rule") -> dict[str, Any]:
    return {
        "uuid": uuid,
        "name": name,
        "metadata": {"schema": "rule::1.0", "tlp": "TLP:CLEAR", "version": "1.0.0"},
    }


def test_registry_indexes_malformed_objects_without_raising(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rules = tmp_path / "objects" / "rules"
    rules.mkdir(parents=True)
    opentide = tmp_path / ".opentide" / "framework" / "schemas"
    opentide.mkdir(parents=True)

    good_uuid = str(uuid4())
    bad_uuid = str(uuid4())
    (rules / "good.yaml").write_text(
        yaml.safe_dump(_minimal_rule(good_uuid, name="good-rule")),
        encoding="utf-8",
    )
    (rules / "bad.yaml").write_text(
        yaml.safe_dump({**_minimal_rule(bad_uuid), "description": None}),
        encoding="utf-8",
    )
    objective = tmp_path / "objects" / "objectives"
    objective.mkdir(parents=True)
    obj_uuid = str(uuid4())
    (objective / "bad-signals.yaml").write_text(
        yaml.safe_dump(
            {
                "uuid": obj_uuid,
                "name": "bad-objective",
                "metadata": {"schema": "objective::1.0", "tlp": "TLP:CLEAR", "version": "1.0.0"},
                "objective": {
                    "description": "x",
                    "signals": [{"name": "no-uuid-signal"}],
                },
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(tmp_path.resolve()))
    index = build_registry()

    assert good_uuid in index["objects"]["rule"]
    assert bad_uuid in index["objects"]["rule"]
    assert obj_uuid in index["objects"]["objective"]
    assert not any(
        value.get("uuid") == "no-uuid-signal"
        for value in index["objects"].get("signal", {}).values()
        if isinstance(value, dict)
    )


def test_validation_reports_all_schema_errors_without_aborting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rules = tmp_path / "objects" / "rules"
    rules.mkdir(parents=True)
    uuids = [str(uuid4()), str(uuid4())]
    for idx, rule_uuid in enumerate(uuids):
        body = _minimal_rule(rule_uuid, name=f"rule-{idx}")
        if idx == 0:
            body["description"] = None
        if idx == 1:
            body.pop("name")
        (rules / f"rule-{idx}.yaml").write_text(yaml.safe_dump(body), encoding="utf-8")

    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(tmp_path.resolve()))

    report = run_validation(checks=frozenset({ValidateCheck.schema}))

    errored = {issue.object_uuid for issue in report.issues if issue.code == "schema_validation"}

    def uuid_in_issues(uuid: str) -> bool:
        return uuid in errored or any(uuid in (issue.object_uuid or "") for issue in report.issues)

    assert uuid_in_issues(uuids[0])
    assert uuid_in_issues(uuids[1])
    assert len(report.issues) >= 2


def test_chaining_graph_is_in_memory_from_threat_index() -> None:
    threats = {
        "a": {
            "threat": {
                "chaining": [
                    {"relation": "follows", "vector": "b"},
                    {"relation": "invalid"},
                ]
            }
        },
        "b": {"threat": {}},
    }
    from opentide.core.chaining import compute_chains

    graph = compute_chains(threats)
    assert graph["a"]["follows"] == ["b"]
    assert "invalid" not in graph.get("a", {})
