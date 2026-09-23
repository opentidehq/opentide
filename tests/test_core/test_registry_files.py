"""SDK: loaded objects point at the file they were read from (issue #297).

``OpenTide.Rules`` built each rule's ``file`` as ``<rules folder>/<basename>``,
so a rule in ``objects/rules/team-a/x.yaml`` pointed at ``objects/rules/x.yaml``:
another rule's file, or one that does not exist.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from tests.validation_support import (
    NESTED_TWIN_LAYOUT,
    assert_objects_point_at_their_files,
    write_nested_twins,
)

from opentide import OpenTide
from opentide.core.registry import OpenTideRegistry


def _twins(object_type: str) -> set[str]:
    return {uuid for kind, uuid in NESTED_TWIN_LAYOUT.values() if kind == object_type}


@pytest.mark.parametrize("accessor", ["OpenTide.Rules", "OpenTide.Models.Rules"])
def test_every_loaded_object_points_at_the_file_that_declares_it(
    tide_corpus_repo: Path, accessor: str
) -> None:
    real_paths = write_nested_twins(tide_corpus_repo)

    rules = OpenTide.Rules if accessor == "OpenTide.Rules" else OpenTide.Models.Rules

    assert _twins("rule") <= set(rules)
    assert assert_objects_point_at_their_files(rules) == len(rules)
    for uuid in _twins("rule"):
        assert Path(rules[uuid].file or "").resolve() == real_paths[uuid]
    for object_type, loaded in (("threat", OpenTide.Threats), ("objective", OpenTide.Objectives)):
        assert _twins(object_type) <= set(loaded)
        assert_objects_point_at_their_files(loaded)


def _registry(index: dict[str, Any]) -> OpenTideRegistry:
    registry = OpenTideRegistry()
    registry._index = index
    registry._initialised = True
    return registry


def _index(rule_payload: dict[str, Any], **extra: Any) -> dict[str, Any]:
    uuid = rule_payload["metadata"]["uuid"]
    return {
        "objects": {"rule": {uuid: rule_payload}, "threat": {}, "objective": {}},
        "files": {uuid: "x.yaml"},
        "paths": {"rule": "/repo/objects/rules"},
        "configurations": {},
        **extra,
    }


def test_a_rule_file_comes_from_file_paths_not_the_basename(rule_payload: dict[str, Any]) -> None:
    uuid = rule_payload["metadata"]["uuid"]
    registry = _registry(
        _index(rule_payload, file_paths={uuid: "/repo/objects/rules/team-a/x.yaml"})
    )

    assert registry.Rules[uuid].file == Path("/repo/objects/rules/team-a/x.yaml")
    assert _registry(registry.Index).Models.Rules[uuid].file == Path(
        "/repo/objects/rules/team-a/x.yaml"
    )


def test_a_rule_missing_from_file_paths_gets_no_guessed_file(
    rule_payload: dict[str, Any],
) -> None:
    uuid = rule_payload["metadata"]["uuid"]
    registry = _registry(_index(rule_payload, file_paths={}))

    assert registry.Rules[uuid].file is None


def test_an_index_without_file_paths_still_joins_the_basename(
    rule_payload: dict[str, Any],
) -> None:
    uuid = rule_payload["metadata"]["uuid"]
    registry = _registry(_index(rule_payload))

    assert registry.Rules[uuid].file == Path("/repo/objects/rules/x.yaml")
