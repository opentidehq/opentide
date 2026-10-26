"""CLI helpers that list object files read the catalogue, not every subfolder (#584)."""

from __future__ import annotations

from pathlib import Path

import pytest

_LAYOUT = (
    "objects/rules/top.yaml",
    "objects/rules/short.yml",
    "objects/rules/scratch.debug.yaml",
    "objects/rules/team/nested.yaml",
    "objects/rules/team/deep/nested.yml",
)


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    for relative in _LAYOUT:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("name: x\nmetadata:\n  uuid: 00000000-0000-4000-8000-000000000001\n")
    return tmp_path


_CATALOGUE = ["short.yml", "top.yaml"]


def test_validate_watch_snapshots_the_catalogue(workspace: Path) -> None:
    from opentide.cli.ui.watch import object_files

    assert [p.name for p in object_files([workspace / "objects" / "rules"])] == _CATALOGUE


def test_completion_offers_only_catalogue_files(workspace: Path) -> None:
    from opentide.cli.completion import iter_object_paths

    paths = [path for _, path in iter_object_paths(workspace, ("rule",))]
    assert sorted(path.name for path in paths) == _CATALOGUE


def test_home_counts_the_catalogue(workspace: Path) -> None:
    from opentide.cli.ui.home import gather

    assert gather("1.0", workspace).catalogue["rules"] == 2


def test_rules_unreviewed_sees_no_rule_in_a_subfolder(tmp_path: Path) -> None:
    from opentide.cli.services.rules import _has_rule_files

    nested = tmp_path / "objects" / "rules" / "team" / "x.yaml"
    nested.parent.mkdir(parents=True)
    nested.write_text("name: x\n")
    assert _has_rule_files(tmp_path) is False
    (tmp_path / "objects" / "rules" / "x.yml").write_text("name: x\n")
    assert _has_rule_files(tmp_path) is True
