"""Signal index keeps the authored ``parent`` and records the objective as ``owner`` (#585)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
import yaml

from opentide.core.index_manager import IndexManager
from opentide.core.registry import Opentide
from opentide.export.explorer_export import _count_relations, _infer_type
from opentide.generation import framework as fw
from opentide.indexing.inflight import apply_inflight_overlay
from opentide.registry.builder import build_registry
from opentide.registry.signals import index_objective_signals
from opentide.validation.checks.kinds import ValidateCheck
from opentide.validation.session import run_validation


@pytest.fixture(autouse=True)
def _reset_index_cache() -> None:
    IndexManager._cache = None
    Opentide._initialised = False
    Opentide._index = None
    yield
    IndexManager._cache = None
    Opentide._initialised = False
    Opentide._index = None


def _objective(uuid: str, name: str, signals: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "name": name,
        "metadata": {
            "uuid": uuid,
            "schema": "objective::1.0",
            "tlp": "TLP:CLEAR",
            "version": 1,
        },
        "objective": {"description": "x", "signals": signals},
    }


def _write_objectives(tmp_path: Path, objectives: dict[str, dict[str, Any]]) -> None:
    folder = tmp_path / "objects" / "objectives"
    folder.mkdir(parents=True)
    for file_name, body in objectives.items():
        (folder / file_name).write_text(yaml.safe_dump(body), encoding="utf-8")


def test_registry_keeps_authored_parent_and_records_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    objective_uuid = str(uuid4())
    base_signal = str(uuid4())
    child_signal = str(uuid4())
    _write_objectives(
        tmp_path,
        {
            "o.yaml": _objective(
                objective_uuid,
                "Objective",
                [
                    {"uuid": base_signal, "name": "Base"},
                    {"uuid": child_signal, "name": "Child", "parent": base_signal},
                ],
            )
        },
    )
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(tmp_path.resolve()))

    signals = build_registry()["objects"]["signal"]

    assert signals[child_signal]["parent"] == base_signal
    assert signals[child_signal]["owner"] == objective_uuid
    assert "parent" not in signals[base_signal]
    assert signals[base_signal]["owner"] == objective_uuid


def test_registry_keeps_the_first_of_two_signals_sharing_a_uuid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first, second, shared = str(uuid4()), str(uuid4()), str(uuid4())
    _write_objectives(
        tmp_path,
        {
            "a.yaml": _objective(first, "A", [{"uuid": shared, "name": "From A"}]),
            "b.yaml": _objective(second, "B", [{"uuid": shared, "name": "From B"}]),
        },
    )
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(tmp_path.resolve()))

    signal = build_registry()["objects"]["signal"][shared]

    assert signal["owner"] == first
    assert signal["name"] == "From A"


def test_inflight_overlay_keeps_authored_parent() -> None:
    objective_uuid = str(uuid4())
    base_signal, child_signal = str(uuid4()), str(uuid4())
    body = _objective(
        objective_uuid,
        "Inflight objective",
        [
            {"uuid": base_signal, "name": "Base"},
            {"uuid": child_signal, "name": "Child", "parent": base_signal},
        ],
    )
    objects_index: dict[str, Any] = {"threat": {}, "objective": {}, "rule": {}, "signal": {}}

    apply_inflight_overlay(objects_index, {objective_uuid: body})

    assert objects_index["signal"][child_signal]["parent"] == base_signal
    assert objects_index["signal"][child_signal]["owner"] == objective_uuid


def test_reingesting_the_same_objective_replaces_its_own_signals() -> None:
    objective_uuid, signal_uuid = str(uuid4()), str(uuid4())
    bucket: dict[str, Any] = {}
    index_objective_signals(
        bucket,
        objective_uuid,
        _objective(objective_uuid, "O", [{"uuid": signal_uuid, "name": "v1"}]),
    )
    index_objective_signals(
        bucket,
        objective_uuid,
        _objective(objective_uuid, "O", [{"uuid": signal_uuid, "name": "v2"}]),
    )
    assert bucket[signal_uuid]["name"] == "v2"


def test_duplicate_signal_uuid_across_objectives_fails_validate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first, second, shared = str(uuid4()), str(uuid4()), str(uuid4())
    _write_objectives(
        tmp_path,
        {
            "a.yaml": _objective(first, "A", [{"uuid": shared, "name": "From A"}]),
            "b.yaml": _objective(second, "B", [{"uuid": shared, "name": "From B"}]),
        },
    )
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(tmp_path.resolve()))

    report = run_validation(checks=frozenset({ValidateCheck.id_uniqueness}), workers=0)

    duplicates = [issue for issue in report.issues if issue.code == "duplicate_signal_uuid"]
    assert not report.ok
    assert len(duplicates) == 1
    assert duplicates[0].object_uuid == second
    assert duplicates[0].context["signal_uuid"] == shared
    assert duplicates[0].context["original"]["objective"] == first
    assert duplicates[0].file_path is not None
    assert duplicates[0].file_path.name == "b.yaml"


def test_distinct_signal_uuids_pass_validate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_objectives(
        tmp_path,
        {
            "a.yaml": _objective(str(uuid4()), "A", [{"uuid": str(uuid4()), "name": "S"}]),
            "b.yaml": _objective(str(uuid4()), "B", [{"uuid": str(uuid4()), "name": "S"}]),
        },
    )
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(tmp_path.resolve()))

    report = run_validation(checks=frozenset({ValidateCheck.id_uniqueness}), workers=0)

    assert not [issue for issue in report.issues if issue.code == "duplicate_signal_uuid"]


class TestRelationsUseOwner:
    """The objective -> signal hop walks ``owner``; an authored ``parent`` is not that hop."""

    MODELS: dict[str, Any] = {
        "objective": {"o-1": {"objective": {}}},
        "signal": {
            "s-base": {"owner": "o-1"},
            "s-child": {"owner": "o-1", "parent": "s-base"},
        },
        "rule": {"r-1": {"detection_model": "s-child"}},
    }

    @pytest.fixture
    def models(self, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
        def type_of(uuid: str, mute: bool = False) -> str | None:
            del mute
            for object_type, bodies in self.MODELS.items():
                if uuid in bodies:
                    return object_type
            return None

        monkeypatch.setattr(fw.MODELS_INDEX, "_loader", lambda: self.MODELS)
        monkeypatch.setattr(fw, "_RELATION_INDEX", {"_source": None, "childs": {}})
        monkeypatch.setattr(fw, "get_type", type_of)
        return self.MODELS

    def test_objective_links_to_its_signals(self, models: dict[str, Any]) -> None:
        assert fw.childs("o-1") == ["s-base", "s-child"]

    def test_signal_parents_are_its_owner(self, models: dict[str, Any]) -> None:
        assert fw.parents("s-child") == ["o-1"]

    def test_coverage_tree_walks_objective_signal_rule(self, models: dict[str, Any]) -> None:
        signals = [child for child in fw.childs("o-1") if fw.get_type(child) == "signal"]
        assert signals == ["s-base", "s-child"]
        assert fw.childs("s-child") == ["r-1"]
        assert fw.childs("s-base") == []


def test_explorer_export_reads_owner() -> None:
    flat = {
        "o-1": {"objective": {"signals": []}},
        "s-1": {"name": "S", "owner": "o-1", "parent": "s-0"},
    }
    assert _infer_type(flat["s-1"]) == "signal"
    assert _count_relations("o-1", flat) == 1
    assert _count_relations("s-1", flat) == 1


def _bump(body: dict[str, Any]) -> dict[str, Any]:
    body["metadata"]["version"] = 2
    return body


@pytest.mark.parametrize("b_first", [True, False])
def test_inflight_overlay_moving_a_signal_reassigns_its_owner(b_first: bool) -> None:
    """A PR that moves a signal from A to B must index it under B, whatever the shard order."""
    a_uuid, b_uuid, moved = str(uuid4()), str(uuid4()), str(uuid4())
    objects_index: dict[str, Any] = {"threat": {}, "objective": {}, "rule": {}, "signal": {}}
    a_body = _objective(a_uuid, "A", [{"uuid": moved, "name": "Moved"}])
    b_body = _objective(b_uuid, "B", [])
    objects_index["objective"] = {a_uuid: a_body, b_uuid: b_body}
    index_objective_signals(objects_index["signal"], a_uuid, a_body)

    shards = {
        a_uuid: _bump(_objective(a_uuid, "A", [])),
        b_uuid: _bump(_objective(b_uuid, "B", [{"uuid": moved, "name": "Moved"}])),
    }
    ordered = dict(reversed(shards.items())) if b_first else shards

    apply_inflight_overlay(objects_index, ordered)

    assert objects_index["signal"][moved]["owner"] == b_uuid


def test_inflight_overlay_drops_signals_its_objective_no_longer_defines() -> None:
    objective_uuid, kept, removed = str(uuid4()), str(uuid4()), str(uuid4())
    body = _objective(
        objective_uuid, "O", [{"uuid": kept, "name": "Kept"}, {"uuid": removed, "name": "Gone"}]
    )
    objects_index: dict[str, Any] = {
        "threat": {},
        "objective": {objective_uuid: body},
        "rule": {},
        "signal": {},
    }
    index_objective_signals(objects_index["signal"], objective_uuid, body)

    shard = _bump(_objective(objective_uuid, "O", [{"uuid": kept, "name": "Kept"}]))
    apply_inflight_overlay(objects_index, {objective_uuid: shard})

    assert kept in objects_index["signal"]
    assert removed not in objects_index["signal"]


def test_inflight_overlay_keeps_a_true_duplicate_on_its_committed_owner() -> None:
    """B's shard reusing a UUID A still defines is a duplicate: A keeps it."""
    a_uuid, b_uuid, shared = str(uuid4()), str(uuid4()), str(uuid4())
    a_body = _objective(a_uuid, "A", [{"uuid": shared, "name": "From A"}])
    objects_index: dict[str, Any] = {
        "threat": {},
        "objective": {a_uuid: a_body},
        "rule": {},
        "signal": {},
    }
    index_objective_signals(objects_index["signal"], a_uuid, a_body)

    shard = _objective(b_uuid, "B", [{"uuid": shared, "name": "From B"}])
    apply_inflight_overlay(objects_index, {b_uuid: shard})

    assert objects_index["signal"][shared]["owner"] == a_uuid


def test_same_objective_duplicate_keeps_the_first_definition() -> None:
    objective_uuid, shared = str(uuid4()), str(uuid4())
    bucket: dict[str, Any] = {}
    index_objective_signals(
        bucket,
        objective_uuid,
        _objective(
            objective_uuid, "O", [{"uuid": shared, "name": "One"}, {"uuid": shared, "name": "Two"}]
        ),
    )
    assert bucket[shared]["name"] == "One"


def test_duplicate_signal_uuid_within_one_objective_fails_validate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    objective_uuid, shared = str(uuid4()), str(uuid4())
    _write_objectives(
        tmp_path,
        {
            "o.yaml": _objective(
                objective_uuid,
                "O",
                [{"uuid": shared, "name": "One"}, {"uuid": shared, "name": "Two"}],
            )
        },
    )
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(tmp_path.resolve()))

    report = run_validation(checks=frozenset({ValidateCheck.id_uniqueness}), workers=0)

    assert [issue.code for issue in report.issues].count("duplicate_signal_uuid") == 1
