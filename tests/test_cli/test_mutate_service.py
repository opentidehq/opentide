"""CLI mutate service behaviour."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from opentide.cli.context import CliContext
from opentide.cli.services import mutate as mutate_service


def test_run_mutate_all_invokes_pipeline() -> None:
    ctx = CliContext(json_output=True)
    with (
        patch.object(mutate_service, "run_mutate_all") as mock_all,
        patch.object(mutate_service, "run_mutate_promote") as mock_promote,
    ):
        result = mutate_service.run_mutate(ctx)
    mock_all.assert_called_once()
    mock_promote.assert_not_called()
    assert result["message"] == "Full mutation pipeline completed"


@pytest.mark.parametrize(
    ("action", "runner", "message"),
    [
        ("promote", "run_mutate_promote", "Promotion completed"),
        ("rename", "run_mutate_rename", "Rename completed"),
        ("references", "run_mutate_references", "References completed"),
        ("security-domain", "run_mutate_security_domain", "Security domain completed"),
    ],
)
def test_run_mutate_dispatches_action(action: str, runner: str, message: str) -> None:
    ctx = CliContext(json_output=True)
    with patch.object(mutate_service, runner) as mock_runner:
        result = mutate_service.run_mutate(ctx, action=action, files=["rule.yaml"])
    mock_runner.assert_called_once()
    assert result["action"] == action
    assert result["message"] == message


def test_run_mutate_unknown_action_raises() -> None:
    ctx = CliContext(json_output=True)
    with pytest.raises(ValueError, match="Unknown mutate action"):
        mutate_service.run_mutate(ctx, action="invalid")


def test_run_mutate_promote_uses_modified_files_when_none_passed() -> None:
    with (
        patch("opentide.deployment.DeploymentStrategy.load_from_environment") as mock_plan,
        patch("opentide.deployment.modified_mdr_files", return_value=["a.yaml"]) as mock_modified,
        patch("opentide.mutation.promotion.PromoteMDR") as mock_promote_cls,
    ):
        mock_promote_cls.return_value = MagicMock()
        mutate_service.run_mutate_promote(None)
    mock_modified.assert_called_once_with(mock_plan.return_value)
    mock_promote_cls.return_value.promote.assert_called_once()


def test_run_mutate_rename_delegates() -> None:
    with patch("opentide.mutation.file_name.run") as mock_run:
        mutate_service.run_mutate_rename()
    mock_run.assert_called_once()


def test_run_mutate_references_delegates() -> None:
    with patch("opentide.mutation.references.run") as mock_run:
        mutate_service.run_mutate_references()
    mock_run.assert_called_once()


def test_run_mutate_security_domain_delegates() -> None:
    with patch("opentide.mutation.security_domain.run") as mock_run:
        mutate_service.run_mutate_security_domain()
    mock_run.assert_called_once()


def test_run_mutate_all_delegates() -> None:
    with (
        patch("opentide.mutation.file_name.run") as mock_file,
        patch("opentide.mutation.references.run") as mock_refs,
        patch("opentide.mutation.security_domain.run") as mock_domain,
    ):
        mutate_service.run_mutate_all()
    mock_file.assert_called_once()
    mock_refs.assert_called_once()
    mock_domain.assert_called_once()
