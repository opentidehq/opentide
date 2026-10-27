"""SDK: loaded objects point at the file they were read from (issue #297).

Files in subfolders are not object instances (#584) and are not loaded at all.

``Opentide.Rules`` built each rule's ``file`` as ``<rules folder>/<basename>``,
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

from opentide import Opentide
from opentide.core.registry import OpentideRegistry


def _twins(object_type: str, *, direct: bool) -> set[str]:
    """Twins of *object_type* directly in their folder, or in a subfolder (#584)."""
    return {
        uuid
        for relative, (kind, uuid) in NESTED_TWIN_LAYOUT.items()
        if kind == object_type and (relative.count("/") == 2) is direct
    }


@pytest.mark.parametrize("accessor", ["Opentide.Rules", "Opentide.Models.Rules"])
def test_every_loaded_object_points_at_the_file_that_declares_it(
    tide_corpus_repo: Path, accessor: str
) -> None:
    real_paths = write_nested_twins(tide_corpus_repo)

    rules = Opentide.Rules if accessor == "Opentide.Rules" else Opentide.Models.Rules

    assert _twins("rule", direct=True) <= set(rules)
    assert _twins("rule", direct=False).isdisjoint(rules)
    assert assert_objects_point_at_their_files(rules) == len(rules)
    for uuid in _twins("rule", direct=True):
        assert Path(rules[uuid].file or "").resolve() == real_paths[uuid]
    for object_type, loaded in (("threat", Opentide.Threats), ("objective", Opentide.Objectives)):
        assert _twins(object_type, direct=True) <= set(loaded)
        assert _twins(object_type, direct=False).isdisjoint(loaded)
        assert_objects_point_at_their_files(loaded)


def _registry(index: dict[str, Any]) -> OpentideRegistry:
    registry = OpentideRegistry()
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
