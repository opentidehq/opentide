"""Documentation CLI module."""

from __future__ import annotations

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
