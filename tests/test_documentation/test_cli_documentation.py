"""Documentation CLI module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from opentide.documentation.cli import run, run_index, run_objects
from opentide.documentation.types import DocumentScope


def test_run_index_writes_catalog() -> None:
    ctx = MagicMock()
    with (
        patch("opentide.documentation.cli.build_catalog") as mock_catalog,
        patch("opentide.documentation.cli.targets"),
        patch("opentide.documentation.cli.write_index") as mock_write,
    ):
        mock_catalog.return_value = MagicMock(rules=[], objectives=[], threats=[])
        run_index(ctx)
    mock_write.assert_called_once()


def test_run_objects_all_scopes() -> None:
    ctx = MagicMock()
    record = MagicMock(name="Item", uuid="u1", model=MagicMock())
    catalog = MagicMock(rules=[record], objectives=[record], threats=[record])
    pub = MagicMock()
    with (
        patch("opentide.documentation.cli.build_catalog", return_value=catalog),
        patch("opentide.documentation.cli.targets", return_value=pub),
        patch("opentide.documentation.cli.write_page") as mock_write,
        patch("opentide.documentation.cli.page_path", return_value=MagicMock()),
        patch("opentide.documentation.cli.render_rule_page", return_value="rule"),
        patch("opentide.documentation.cli.render_objective_page", return_value="obj"),
        patch("opentide.documentation.cli.render_threat_page", return_value="threat"),
    ):
        counts = run_objects(ctx)
    assert counts == {"rules": 1, "objectives": 1, "threats": 1}
    assert mock_write.call_count == 3


def test_run_full_pipeline() -> None:
    ctx = MagicMock(output_dir="/tmp/docs")
    with (
        patch("opentide.documentation.cli._build_context", return_value=ctx),
        patch(
            "opentide.documentation.cli.run_objects",
            return_value={"rules": 1, "objectives": 0, "threats": 0},
        ),
        patch("opentide.documentation.cli.run_index") as mock_index,
    ):
        result = run()
    mock_index.assert_called_once()
    assert result["counts"]["rules"] == 1


def test_run_index_scope_only() -> None:
    ctx = MagicMock(output_dir="/tmp/docs")
    with (
        patch("opentide.documentation.cli._build_context", return_value=ctx),
        patch("opentide.documentation.cli.run_index") as mock_index,
    ):
        result = run(scope="index")
    mock_index.assert_called_once()
    assert "Index pages written" in result["message"]


def test_run_objects_single_scope() -> None:
    ctx = MagicMock(output_dir="/tmp/docs")
    with (
        patch("opentide.documentation.cli._build_context", return_value=ctx),
        patch(
            "opentide.documentation.cli.run_objects",
            return_value={"rules": 2, "objectives": 0, "threats": 0},
        ),
    ):
        result = run(scope=DocumentScope.rules.value)
    assert result["counts"]["rules"] == 2


def test_run_changed_pipeline_only_targets_selected_pages() -> None:
    ctx = MagicMock(output_dir="/tmp/docs")
    rule = MagicMock(uuid="rule-1", object_type=DocumentScope.rules)
    objective = MagicMock(uuid="objective-1", object_type=DocumentScope.objectives)
    threat = MagicMock(uuid="threat-1", object_type=DocumentScope.threats)
    catalog = MagicMock(rules=[rule], objectives=[objective], threats=[threat])
    with (
        patch("opentide.documentation.cli._build_context", return_value=ctx),
        patch("opentide.documentation.cli.build_catalog", return_value=catalog),
        patch(
            "opentide.documentation.cli._resolve_changed_targets",
            return_value=(
                {Path("Models/rules/rule.yaml")},
                {"rule-1"},
                {"rule-1", "objective-1"},
                [],
            ),
        ),
        patch(
            "opentide.documentation.cli.run_objects",
            return_value={"rules": 1, "objectives": 1, "threats": 0},
        ) as mock_objects,
        patch("opentide.documentation.cli._remove_deleted_pages", return_value=0) as mock_remove,
        patch("opentide.documentation.cli.run_index") as mock_index,
    ):
        result = run(changed=True)
    mock_objects.assert_called_once_with(ctx, target_uuids={"rule-1", "objective-1"})
    mock_remove.assert_called_once_with(ctx, [])
    mock_index.assert_called_once_with(ctx)
    assert result["counts"] == {"rules": 1, "objectives": 1, "threats": 0}
    assert result["targets"] == ["objective-1", "rule-1"]


def test_run_changed_pipeline_noop_when_no_object_changes() -> None:
    ctx = MagicMock(output_dir="/tmp/docs")
    catalog = MagicMock(rules=[], objectives=[], threats=[])
    with (
        patch("opentide.documentation.cli._build_context", return_value=ctx),
        patch("opentide.documentation.cli.build_catalog", return_value=catalog),
        patch(
            "opentide.documentation.cli._resolve_changed_targets",
            return_value=(set(), set(), set(), []),
        ),
        patch("opentide.documentation.cli.run_objects") as mock_objects,
        patch("opentide.documentation.cli.run_index") as mock_index,
    ):
        result = run(changed=True)
    mock_objects.assert_not_called()
    mock_index.assert_not_called()
    assert result["message"] == "No changed object documentation detected"


def test_expand_referrer_closure_walks_upstream() -> None:
    with (
        patch("opentide.documentation.cli.fw.relations_list") as mock_relations,
        patch("opentide.documentation.cli.fw.get_type", return_value="objective"),
    ):
        mock_relations.return_value = {"objective": ["objective-1"]}
        from opentide.documentation.cli import _expand_referrer_closure

        closure = _expand_referrer_closure({"rule-1"})
    mock_relations.assert_called_once_with("rule-1", mode="flat", direction="upstream")
    assert closure == {"rule-1", "objective-1"}


def test_remove_deleted_pages_unlinks_existing_markdown() -> None:
    ctx = MagicMock()
    path = MagicMock()
    path.exists.return_value = True
    pub = MagicMock(rules_dir=Path("/docs/Rules"))
    with (
        patch("opentide.documentation.cli.targets", return_value=pub),
        patch("opentide.documentation.cli.page_path", return_value=path),
    ):
        from opentide.documentation.cli import _remove_deleted_pages

        removed = _remove_deleted_pages(ctx, [("rule", "rule-1", "Example Rule")])
    path.unlink.assert_called_once_with()
    assert removed == 1


def test_changed_targets_read_only_catalogue_files(tmp_path: Path) -> None:
    """``docs --changed`` follows the catalogue (#584): direct ``.yaml``/``.yml`` children only.

    Moving ``objects/rules/team/moved.yaml`` up into ``objects/rules/`` (what the
    ``nested_object_file`` warning asks for) must not report the old nested path
    as a deleted object: that would unlink the page just written for the moved file.
    """
    from opentide.core.git_baseline import ChangedPath
    from opentide.documentation.cli import _changed_object_paths_and_uuids

    rules = tmp_path / "objects" / "rules"
    (rules / "team").mkdir(parents=True)
    body = "name: Moved Rule\nuuid: rule-moved\n"
    (rules / "moved.yaml").write_text(body, encoding="utf-8")
    (rules / "other.yml").write_text("name: Other\nuuid: rule-yml\n", encoding="utf-8")
    (rules / "team" / "nested.yaml").write_text("name: N\nuuid: rule-nested\n", encoding="utf-8")
    changes = [
        ChangedPath(relative=Path(rel), absolute=tmp_path / rel)
        for rel in (
            "objects/rules/team/moved.yaml",
            "objects/rules/moved.yaml",
            "objects/rules/other.yml",
            "objects/rules/team/nested.yaml",
        )
    ]
    registry = MagicMock(Index={"paths": {"rule": str(rules)}})
    with (
        patch("opentide.core.registry.Opentide", registry),
        patch("opentide.core.git_baseline.resolve_baseline", return_value=MagicMock(commit="b")),
        patch("opentide.core.git_baseline.changed_paths", return_value=changes),
        patch("opentide.documentation.cli._git_stdout", return_value=body),
    ):
        paths, uuids, deleted = _changed_object_paths_and_uuids(tmp_path)

    assert deleted == []
    assert uuids == {"rule-moved", "rule-yml"}
    assert paths == {Path("objects/rules/moved.yaml"), Path("objects/rules/other.yml")}
