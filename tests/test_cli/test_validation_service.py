"""CLI validation service behaviour."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opentide.cli.context import CliContext
from opentide.cli.enums import ValidateCheck
from opentide.cli.exit_codes import CiOutcome
from opentide.cli.services import validation as validation_service
from opentide.validation.issues import ValidationIssue, ValidationReport

FAILED_OUTCOME = CiOutcome(exit_code=1, failed=True, warned=False)
CLEAN_OUTCOME = CiOutcome(exit_code=0, failed=False, warned=False)


@pytest.fixture(autouse=True)
def tenantless() -> Iterator[MagicMock]:
    """Every platform has a tenant unless a test says otherwise."""
    with patch("opentide.platforms.enabled.systems_without_tenants", return_value=[]) as mock:
        yield mock


@pytest.fixture(autouse=True)
def no_inherited_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    """``DEPLOYMENT_PLAN`` was removed in 0.17.0; a set one fails ``validate query``."""
    monkeypatch.delenv("DEPLOYMENT_PLAN", raising=False)


@pytest.fixture(autouse=True)
def reached() -> Iterator[MagicMock]:
    """Every selected rule reaches one tenant unless a test says otherwise."""
    with patch.object(
        validation_service, "queries_per_tenant", return_value={"tenant-a": 1}
    ) as mock:
        yield mock


def test_run_validate_cve_delegates_to_session() -> None:
    ctx = CliContext(json_output=True)
    report = ValidationReport(ok=True)
    with (
        patch.object(validation_service, "run_validation", return_value=report) as mock_run,
        patch("opentide.cli.exit_codes.validation_outcome", return_value=CLEAN_OUTCOME),
    ):
        result = validation_service.run_validate(ctx, check=ValidateCheck.cve)
    mock_run.assert_called_once()
    assert mock_run.call_args.kwargs["checks"] == frozenset({ValidateCheck.cve})
    assert result["check"] == "cve"
    assert result["status"] == "passed"
    assert result["_exit_code"] == 0


def test_run_validate_cve_failure_sets_exit_code() -> None:
    ctx = CliContext(json_output=True)
    report = ValidationReport(
        ok=False,
        issues=[ValidationIssue(code="cve", message="unknown CVE")],
    )
    with (
        patch.object(validation_service, "run_validation", return_value=report),
        patch("opentide.cli.exit_codes.validation_outcome", return_value=FAILED_OUTCOME),
    ):
        result = validation_service.run_validate(ctx, check=ValidateCheck.cve)
    assert result["status"] == "failed"
    assert result["_exit_code"] == 1


def test_run_validate_cve_skips_run_cve_validation_helper() -> None:
    ctx = CliContext(json_output=True)
    report = ValidationReport(ok=True)
    with (
        patch.object(validation_service, "run_cve_validation") as mock_cve,
        patch.object(validation_service, "run_validation", return_value=report),
        patch("opentide.cli.exit_codes.validation_outcome", return_value=CLEAN_OUTCOME),
    ):
        validation_service.run_validate(ctx, check=ValidateCheck.cve)
    mock_cve.assert_not_called()


def test_run_validate_scope_no_match_report() -> None:
    ctx = CliContext(json_output=True)
    report = ValidationReport(
        ok=False,
        issues=[ValidationIssue(code="scope_no_match", message="No objects matched")],
    )
    with (
        patch.object(validation_service, "run_validation", return_value=report),
        patch("opentide.cli.exit_codes.validation_outcome", return_value=FAILED_OUTCOME),
    ):
        result = validation_service.run_validate(
            ctx,
            uuids=["00000000-0000-4000-8000-000000000099"],
        )
    assert result["report"]["ok"] is False
    assert result["status"] == "failed"


def test_run_validate_all_default_checks() -> None:
    report = ValidationReport(ok=True, stats={"objects_checked": 1})
    with patch.object(validation_service, "run_validation", return_value=report):
        results = validation_service.run_validate_all()
    assert results["id-uniqueness"]["status"] == "passed"


def test_run_validate_all_schema_failure_does_not_fail_other_checks() -> None:
    report = ValidationReport(
        ok=False,
        issues=[
            ValidationIssue(
                code="schema_validation",
                message="threat.actors: Input should be a valid dictionary",
                field_path=("threat", "actors"),
            )
        ],
    )
    with patch.object(validation_service, "run_validation", return_value=report):
        results = validation_service.run_validate_all()
    assert results["schema"]["status"] == "failed"
    assert results["id-uniqueness"]["status"] == "passed"
    assert results["uuid-format"]["status"] == "passed"
    assert results["id-uniqueness"]["issues"] == []
    assert results["schema"]["issues"]


def test_run_validate_all_counts_schema_missing_against_schema() -> None:
    """#582: an object without ``metadata.schema`` fails the schema check."""
    report = ValidationReport(
        ok=False,
        issues=[
            ValidationIssue(
                code="schema_missing",
                message="missing metadata.schema on object",
                field_path=("metadata", "schema"),
            )
        ],
    )
    with patch.object(validation_service, "run_validation", return_value=report):
        results = validation_service.run_validate_all()
    assert results["schema"]["status"] == "failed"
    assert [issue["code"] for issue in results["schema"]["issues"]] == ["schema_missing"]


def test_run_validate_check_id_uniqueness() -> None:
    report = ValidationReport(ok=True)
    with patch.object(validation_service, "run_validation", return_value=report):
        payload = validation_service.run_validate_check(ValidateCheck.id_uniqueness)
    assert payload["status"] == "passed"


def test_run_id_uniqueness_uuid_and_schema_wrappers() -> None:
    report = ValidationReport(ok=True)
    with patch.object(validation_service, "run_validation", return_value=report) as mock_run:
        validation_service.run_id_uniqueness()
        validation_service.run_uuid_format()
        validation_service.run_schema_validation()
    assert mock_run.call_count == 3


def test_run_validate_default_checks_payload() -> None:
    ctx = CliContext(json_output=True)
    report = ValidationReport(ok=True, stats={"objects_checked": 2})
    with (
        patch.object(validation_service, "run_validation", return_value=report),
        patch("opentide.cli.exit_codes.validation_outcome", return_value=CLEAN_OUTCOME),
    ):
        result = validation_service.run_validate(ctx, file="objects/rules/x.yaml")
    assert "checks" in result
    assert "report" in result
    assert result["checks"]["id-uniqueness"]["status"] == "passed"
    assert result["checks"]["schema"]["status"] == "passed"


def _payload_for(check: ValidateCheck | None, report: ValidationReport) -> dict[str, object]:
    with (
        patch.object(validation_service, "run_validation", return_value=report),
        patch("opentide.cli.exit_codes.validation_outcome", return_value=CLEAN_OUTCOME),
        patch.object(validation_service, "discover_workspace", return_value=Path("/ws")),
    ):
        return validation_service.run_validate(CliContext(json_output=True), check=check)


@pytest.mark.parametrize("check", [None, ValidateCheck.schema, ValidateCheck.id_uniqueness])
def test_every_invocation_puts_the_report_in_the_same_place(check: ValidateCheck | None) -> None:
    """#487: selecting a check used to relocate the report to ``issues``.

    A consumer then had to read ``report.issues`` for a bare run and
    ``issues.issues`` for ``--check``, from one command. The report must be at
    one path regardless of how validate was invoked.
    """
    report = ValidationReport(
        ok=False,
        issues=[ValidationIssue(code="schema_validation", message="bad")],
    )
    payload = _payload_for(check, report)

    assert "report" in payload, "the report moved; consumers break"
    assert payload["report"]["issues"], "the report is present but empty"
    assert "issues" not in payload, "the report is duplicated at the top level"
    assert "errors" not in payload, "the legacy errors map is back"


def test_selecting_a_check_changes_only_the_checks_map() -> None:
    """The narrow invocation must be the broad one minus untouched checks."""
    report = ValidationReport(ok=True, stats={"objects_checked": 1})
    broad = _payload_for(None, report)
    narrow = _payload_for(ValidateCheck.schema, report)

    # `check` names the selection and is the ONLY permitted extra key.
    assert set(narrow) - set(broad) == {"check"}
    assert set(broad) - set(narrow) == set()
    assert narrow["check"] == "schema"

    assert list(broad["checks"]) == list(validation_service.DEFAULT_CHECK_NAMES)
    assert list(narrow["checks"]) == ["schema"]

    # Everything outside `checks` is identical.
    assert {k: v for k, v in broad.items() if k != "checks"} == {
        k: v for k, v in narrow.items() if k not in {"checks", "check"}
    }


def test_single_check_payload_matches_the_cli_shape() -> None:
    """``run_validate_check`` must not reintroduce a third shape."""
    report = ValidationReport(ok=True)
    with patch.object(validation_service, "run_validation", return_value=report):
        payload = validation_service.run_validate_check(ValidateCheck.schema)
    assert "report" in payload
    assert list(payload["checks"]) == ["schema"]
    assert "errors" not in payload


def _validate_against(workspace: Path, objects_checked: int, **kwargs: object) -> dict[str, object]:
    report = ValidationReport(ok=True, stats={"objects_checked": objects_checked})
    with (
        patch.object(validation_service, "run_validation", return_value=report),
        patch.object(validation_service, "discover_workspace", return_value=workspace),
    ):
        return validation_service.run_validate(CliContext(json_output=True), **kwargs)


def test_run_validate_reports_the_workspace_it_scanned(tmp_path: Path) -> None:
    result = _validate_against(tmp_path, 3, strict=True)
    assert result["workspace"] == str(tmp_path)
    assert result["message"] == "Validation passed"


@pytest.mark.parametrize("strict", [False, True])
def test_an_empty_catalogue_names_the_workspace_and_still_passes(
    tmp_path: Path, strict: bool
) -> None:
    """#294: from the wrong directory, a bare "Validation passed" had checked nothing."""
    result = _validate_against(tmp_path, 0, strict=strict)
    assert result["message"] == (
        f"Validation passed, but no detection objects were found under {tmp_path}"
    )
    assert result["status"] == "passed"
    assert result["_exit_code"] == 0
    assert "warnings" not in result


def test_a_single_non_object_check_keeps_the_plain_message(tmp_path: Path) -> None:
    """``id-uniqueness`` alone never counts objects, so zero says nothing."""
    result = _validate_against(tmp_path, 0, check=ValidateCheck.id_uniqueness)
    assert result["message"] == "Validation passed"
    assert result["workspace"] == str(tmp_path)


def test_run_validate_default_checks_schema_only_failure() -> None:
    ctx = CliContext(json_output=True)
    report = ValidationReport(
        ok=False,
        issues=[ValidationIssue(code="schema_validation", message="invalid")],
    )
    with (
        patch.object(validation_service, "run_validation", return_value=report),
        patch("opentide.cli.exit_codes.validation_outcome", return_value=FAILED_OUTCOME),
    ):
        result = validation_service.run_validate(ctx)
    assert result["checks"]["schema"]["status"] == "failed"
    assert result["checks"]["id-uniqueness"]["status"] == "passed"
    assert result["checks"]["uuid-format"]["status"] == "passed"


def test_run_validate_all_uuid_failure_does_not_fail_schema() -> None:
    report = ValidationReport(
        ok=False,
        issues=[ValidationIssue(code="invalid_uuid", message="not uuidv4")],
    )
    with patch.object(validation_service, "run_validation", return_value=report):
        results = validation_service.run_validate_all()
    assert results["uuid-format"]["status"] == "failed"
    assert results["schema"]["status"] == "passed"
    assert results["id-uniqueness"]["status"] == "passed"


def test_run_validate_all_duplicate_id_does_not_fail_schema() -> None:
    report = ValidationReport(
        ok=False,
        issues=[ValidationIssue(code="duplicate_id", message="dup")],
    )
    with patch.object(validation_service, "run_validation", return_value=report):
        results = validation_service.run_validate_all()
    assert results["id-uniqueness"]["status"] == "failed"
    assert results["schema"]["status"] == "passed"


def test_run_validate_check_schema_failure() -> None:
    report = ValidationReport(
        ok=False,
        issues=[ValidationIssue(code="schema", message="invalid")],
    )
    with patch.object(validation_service, "run_validation", return_value=report):
        payload = validation_service.run_validate_check(ValidateCheck.schema)
    assert payload["status"] == "failed"


def test_validate_query_platform_skips_when_no_rules(monkeypatch) -> None:
    ctx = CliContext(json_output=True)
    with (
        patch(
            "opentide.deployment.make_deploy_plan",
            return_value={},
        ),
    ):
        result = validation_service.validate_query_platform(ctx, "sentinel", live=True)
    assert result["status"] == "skipped"
    assert result["strategies"] == ["PREVIEW", "RELEASE"]


def test_validate_query_platform_reads_every_rule_for_both_strategies_by_default() -> None:
    from opentide.models.deployment_enums import DEPLOYABLE_STRATEGIES

    ctx = CliContext(json_output=True)
    with patch("opentide.deployment.make_deploy_plan", return_value={}) as plan:
        validation_service.validate_query_platform(ctx, "sentinel", live=True)
    plan.assert_called_once()
    assert plan.call_args.args[0] == DEPLOYABLE_STRATEGIES
    assert plan.call_args.kwargs["all_files"] is True
    assert plan.call_args.kwargs["scope"] is None
    # A query check never sends DISABLEMENT or DELETION rules.
    assert plan.call_args.kwargs["keep_deprecated"] is False


def test_validate_query_platform_narrows_to_an_explicit_strategy() -> None:
    from opentide.models.deployment_enums import StatusStrategy

    ctx = CliContext(json_output=True)
    with patch("opentide.deployment.make_deploy_plan", return_value={}) as plan:
        result = validation_service.validate_query_platform(
            ctx, "sentinel", live=True, strategies=["release"]
        )
    assert plan.call_args.args[0] == (StatusStrategy.RELEASE,)
    assert result["strategies"] == ["RELEASE"]


@pytest.mark.parametrize(
    ("value", "hint"),
    [
        ("STAGING", "STAGING was a deployment plan, removed in 0.17.0: pass PREVIEW"),
        ("PRODUCTION", "PRODUCTION was a deployment plan, removed in 0.17.0: pass RELEASE"),
        ("FULL", "--strategy PREVIEW --strategy RELEASE --all"),
        ("DELETION", "pass RELEASE"),
    ],
)
def test_validate_query_platform_refuses_a_strategy_that_is_not_deployable(
    value: str, hint: str
) -> None:
    ctx = CliContext(json_output=True)
    with patch("opentide.deployment.make_deploy_plan") as plan:
        result = validation_service.validate_query_platform(
            ctx, "sentinel", live=True, strategies=[value]
        )
    plan.assert_not_called()
    assert result["status"] == "failed"
    assert result["_exit_code"] == 2
    assert "is not a deployable strategy" in str(result["message"])
    assert hint in str(result["message"])


def test_validate_query_platform_refuses_an_inherited_deployment_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from opentide.models.deployment_enums import removed_plan_message

    monkeypatch.setenv("DEPLOYMENT_PLAN", "STAGING")
    ctx = CliContext(json_output=True)
    with patch("opentide.deployment.make_deploy_plan") as plan:
        result = validation_service.validate_query_platform(ctx, "sentinel", live=True)
    plan.assert_not_called()
    assert result["status"] == "failed"
    assert result["_exit_code"] == 2
    assert result["message"] == removed_plan_message("STAGING")
    assert "Use --strategy PREVIEW." in str(result["message"])


def test_validate_query_platform_runs_validator(monkeypatch) -> None:
    ctx = CliContext(json_output=True)
    validator = MagicMock()
    with (
        patch(
            "opentide.deployment.make_deploy_plan",
            return_value={"sentinel": ["u1"]},
        ),
        patch(
            "opentide.platforms.plugins.DeployTide",
        ) as mock_tide,
        patch("opentide.core.registry.Opentide") as mock_ot,
        patch("opentide.cli.exit_codes.validation_outcome", return_value=CLEAN_OUTCOME),
    ):
        mock_tide.return_value.query_validation_for.return_value = {"sentinel": validator}
        mock_ot.Configurations.Systems.Index = {
            "sentinel": {"tide": {"name": "Sentinel"}},
        }
        result = validation_service.validate_query_platform(ctx, "sentinel", live=True)
    validator.validate.assert_called_once()
    from opentide.models.deployment_enums import DEPLOYABLE_STRATEGIES

    assert validator.validate.call_args.kwargs["strategies"] == DEPLOYABLE_STRATEGIES
    assert result["status"] == "passed"
    assert result["mode"] == "live"
    assert result["strategies"] == ["PREVIEW", "RELEASE"]


def test_validate_query_platform_fails_on_unsubstituted_credentials() -> None:
    """A ValueError from the validator fails the check and does not retry as TypeError."""
    ctx = CliContext(json_output=True)
    validator = MagicMock()
    validator.validate.side_effect = ValueError(
        "Azure credentials are unset ($AZURE_TENANT_ID). "
        "Set those environment variables before a live check."
    )
    with (
        patch("opentide.deployment.make_deploy_plan", return_value={"sentinel": ["u1"]}),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.registry.Opentide") as mock_ot,
    ):
        mock_tide.return_value.query_validation_for.return_value = {"sentinel": validator}
        mock_ot.Configurations.Systems.Index = {"sentinel": {"tide": {"name": "Sentinel"}}}
        result = validation_service.validate_query_platform(ctx, "sentinel", live=True)
    assert result["status"] == "failed"
    assert result["_exit_code"] == 1
    assert result["mode"] == "live"
    assert "$AZURE_TENANT_ID" in str(result["message"])
    assert validator.validate.call_count == 1


def test_validate_query_platform_surfaces_retired_tenant_proxy() -> None:
    """A config ValueError from engine load is the check result, not a traceback."""
    ctx = CliContext(json_output=True)
    message = (
        "platforms/splunk.toml [[tenants]]: The proxy key is retired. "
        "Pass the URL with `opentide --proxy http://[user:pass@]host:port`."
    )
    with (
        patch("opentide.deployment.make_deploy_plan", return_value={"splunk": ["u1"]}),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
    ):
        mock_tide.return_value.query_validation_for.side_effect = ValueError(message)
        result = validation_service.validate_query_platform(ctx, "splunk", live=True)
    assert result["status"] == "failed"
    assert result["supported"] is True
    assert result["_exit_code"] == 1
    assert result["mode"] == "live"
    assert "opentide --proxy" in str(result["message"])


def test_validate_query_platform_refuses_without_live() -> None:
    """A bare call names ``--live`` and does not select rules to deploy."""
    ctx = CliContext(json_output=True)

    def _explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("a bare validate query must not select rules to deploy")

    with patch("opentide.deployment.make_deploy_plan", side_effect=_explode):
        result = validation_service.validate_query_platform(ctx, "sentinel")
    assert result["status"] == "failed"
    assert result["supported"] is True
    assert "--live" in str(result["message"])
    assert "mode" not in result


def test_validate_query_live_without_tenants_fails_before_loading_a_validator(
    tenantless: MagicMock,
) -> None:
    """#314: the resolver's bare ``raise Exception`` reached the user as a traceback."""
    ctx = CliContext(json_output=True)
    config = ".opentide/configurations/platforms/splunk.toml"
    tenantless.return_value = ["splunk"]
    with (
        patch("opentide.deployment.make_deploy_plan", return_value={"splunk": ["u1"]}),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.platforms.enabled.platform_config_path", return_value=config),
    ):
        result = validation_service.validate_query_platform(ctx, "splunk", live=True)
    tenantless.assert_called_once_with(["splunk"])
    mock_tide.assert_not_called()
    assert result == {
        "platform": "splunk",
        "mode": "live",
        "status": "failed",
        "supported": True,
        "message": f"Cannot run live query validation: splunk has no tenants configured in {config}",
        "advice": f"add (or uncomment) a [[tenants]] entry in {config}",
        "missing_tenants": {"splunk": config},
        "_exit_code": 1,
    }


def test_validate_query_live_with_a_broken_sdk_advises_a_reinstall() -> None:
    """Every SDK ships with ``pip install opentide``; one that will not import is a damaged
    environment, so the advice is a reinstall and never an extra (the Monflo report)."""
    ctx = CliContext(json_output=True)
    validator = MagicMock()
    validator.validate.side_effect = ModuleNotFoundError("No module named 'azure'", name="azure")
    with (
        patch("opentide.deployment.make_deploy_plan", return_value={"sentinel": ["u1"]}),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.registry.Opentide") as mock_ot,
    ):
        mock_tide.return_value.query_validation_for.return_value = {"sentinel": validator}
        mock_ot.Configurations.Systems.Index = {"sentinel": {"tide": {"name": "Sentinel"}}}
        result = validation_service.validate_query_platform(ctx, "sentinel", live=True)
    assert result["status"] == "failed"
    assert result["_exit_code"] == 1
    assert result["advice"] == "reinstall opentide: pip install --force-reinstall opentide"
    assert "could not import azure" in str(result["message"])
    assert "[" not in str(result["advice"]) + str(result["message"])


def test_run_validate_returns_diagnostics_and_prints_nothing() -> None:
    """The service builds diagnostics; the command renders them as code frames."""
    ctx = CliContext(json_output=False)
    report = ValidationReport(
        ok=False,
        issues=[ValidationIssue(code="schema_validation", message="invalid field")],
    )
    with (
        patch.object(validation_service, "run_validation", return_value=report),
        patch("opentide.cli.exit_codes.validation_outcome", return_value=FAILED_OUTCOME),
    ):
        result = validation_service.run_validate(ctx)
    (diagnostic,) = result["_diagnostics"]
    assert (diagnostic.code, diagnostic.message) == ("schema_validation", "invalid field")
    (issue,) = result["report"]["issues"]
    assert issue["explain"] == "opentide explain schema_validation"
    assert result["_failure_code"] == "issues_found"
    assert result["_summary"] == {
        "objects": 0,
        "errors": 1,
        "warnings": 0,
        "files": 0,
        "warning_files": 0,
    }


def test_files_count_where_the_errors_are(tmp_path: Path) -> None:
    """A file with only a warning is not one of the files with errors."""
    ctx = CliContext(json_output=True)
    report = ValidationReport(
        ok=False,
        issues=[
            ValidationIssue(
                code="vocab_unknown", file_path=tmp_path / "objective.yaml", message="e"
            )
        ],
        warnings=[
            ValidationIssue(
                code="platform_not_enabled",
                severity="warning",
                file_path=tmp_path / "rule.yaml",
                message="w",
            )
        ],
        stats={"objects_checked": 3},
    )
    with (
        patch.object(validation_service, "run_validation", return_value=report),
        patch.object(validation_service, "discover_workspace", return_value=tmp_path),
        patch("opentide.cli.exit_codes.validation_outcome", return_value=FAILED_OUTCOME),
    ):
        summary = validation_service.run_validate(ctx)["_summary"]
    assert summary == {"objects": 3, "errors": 1, "warnings": 1, "files": 1, "warning_files": 1}
    line = validation_service.validate_outcome_line(summary, failed=True, seconds=0.9)
    assert line == "1 error in 1 file · 3 objects checked · 0.9s"


@pytest.mark.parametrize(
    ("summary", "failed", "expected"),
    [
        ({"objects": 3}, False, "3 objects valid · 0.9s"),
        ({"objects": 1, "warnings": 2}, False, "1 object valid · 2 warnings · 0.9s"),
        ({"objects": 0}, False, "Validation passed · 0.9s"),
        (
            {"objects": 3, "errors": 2, "files": 1},
            True,
            "2 errors in 1 file · 3 objects checked · 0.9s",
        ),
        (
            {"objects": 3, "warnings": 1, "files": 0, "warning_files": 1},
            True,
            "1 warning in 1 file · 3 objects checked · 0.9s",
        ),
        ({"errors": 1}, True, "1 error · 0.9s"),
    ],
)
def test_validate_outcome_line(summary: dict[str, int], failed: bool, expected: str) -> None:
    assert (
        validation_service.validate_outcome_line(summary, failed=failed, seconds=0.94) == expected
    )


def test_validate_query_platform_legacy_validator_signature() -> None:
    ctx = CliContext(json_output=True)
    validator = MagicMock()
    validator.validate.side_effect = [TypeError("legacy"), None]
    with (
        patch(
            "opentide.deployment.make_deploy_plan",
            return_value={"sentinel": ["u1"]},
        ),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.registry.Opentide") as mock_ot,
        patch("opentide.cli.exit_codes.validation_outcome", return_value=CLEAN_OUTCOME),
    ):
        mock_tide.return_value.query_validation_for.return_value = {"sentinel": validator}
        mock_ot.Configurations.Systems.Index = {
            "sentinel": {"platform": {"name": "Sentinel"}},
        }
        result = validation_service.validate_query_platform(ctx, "sentinel", live=True)
    assert result["status"] == "passed"
    assert validator.validate.call_count == 2


def test_validate_query_platform_warnings_are_not_fatal() -> None:
    ctx = CliContext(json_output=True)
    warned = CiOutcome(exit_code=0, failed=False, warned=True)
    validator = MagicMock()
    with (
        patch(
            "opentide.deployment.make_deploy_plan",
            return_value={"sentinel": ["u1"]},
        ),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.registry.Opentide") as mock_ot,
        patch("opentide.cli.exit_codes.validation_outcome", return_value=warned),
    ):
        mock_tide.return_value.query_validation_for.return_value = {"sentinel": validator}
        mock_ot.Configurations.Systems.Index = {
            "sentinel": {"tide": {"name": "Sentinel"}},
        }
        result = validation_service.validate_query_platform(ctx, "sentinel", live=True)
    assert result["status"] == "passed"
    assert result["_exit_code"] == 0
    assert result["warnings"]


def test_validate_query_empty_exception_names_the_exception_not_a_plan() -> None:
    ctx = CliContext(json_output=True)
    with (
        patch("opentide.deployment.make_deploy_plan", side_effect=KeyError()),
    ):
        result = validation_service.validate_query_platform(ctx, "sentinel", live=True)
    assert result["status"] == "failed"
    assert "FULL" not in str(result["message"])
    assert "plan" not in str(result["message"])
    assert "KeyError" in str(result["message"])


def test_validate_file_is_repeatable() -> None:
    """The production write-back validates exactly the rule files a deploy modified (#548)."""
    from typer.testing import CliRunner

    from opentide.cli import app

    report = ValidationReport(ok=True, stats={"objects_checked": 2})
    with (
        patch.object(validation_service, "run_validation", return_value=report) as mock_run,
        patch("opentide.cli.exit_codes.validation_outcome", return_value=CLEAN_OUTCOME),
    ):
        result = CliRunner().invoke(
            app,
            ["--json", "validate", "--strict", "--file", "rules/a.yaml", "--file", "rules/b.yaml"],
        )
    assert result.exit_code == 0, result.stdout + result.stderr
    scope = mock_run.call_args.kwargs["scope"]
    assert scope.targets == frozenset({"rules/a.yaml", "rules/b.yaml"})
