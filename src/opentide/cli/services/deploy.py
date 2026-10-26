"""Deployment services for the CLI."""

from __future__ import annotations

import os
import time
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, cast

import structlog

from opentide.cli.enums import DetectionPlatform
from opentide.cli.ui.contract import (
    USAGE_INVALID_CHOICE,
    USAGE_INVALID_VALUE,
    USAGE_MISSING_OPTION,
    did_you_mean,
)
from opentide.core.index_manager import IndexManager
from opentide.core.logging.config import get_stdout_console

logger = structlog.get_logger("opentide.cli.services.deploy")
if TYPE_CHECKING:
    from opentide.cli.context import CliContext
    from opentide.models.deployment_enums import RunStrategies


_NO_RULES_MATCHED = "No rule this run read has a status that maps to its strategies"


def _tenant_targets(
    system: str, uuids: list[str], run: RunStrategies, wide: bool
) -> dict[str, list[str]]:
    """Which tenants a deploy would reach on *system*, and with which rules."""
    from opentide.deployment.planning import TideDeployment, wide_scope
    from opentide.models.deployment_enums import DetectionPlatforms

    platform = DetectionPlatforms[system.upper()]
    if wide:
        with wide_scope():
            deployment = TideDeployment(uuids, platform, run)
    else:
        deployment = TideDeployment(uuids, platform, run)
    return {
        batch.tenant.name: [str(rule.metadata.uuid) for rule in batch.rules]
        for batch in deployment.rule_deployment
    }


def unset_variables_warning(names: list[str]) -> str:
    """``a real deploy would need $A and $B, which are unset``."""
    shown = [f"${name}" for name in names]
    listed = shown[0] if len(shown) == 1 else f"{', '.join(shown[:-1])} and {shown[-1]}"
    which = "which is unset" if len(shown) == 1 else "which are unset"
    return f"a real deploy would need {listed}, {which}"


def compile_diagnostics(payloads: dict[str, list[dict[str, object]]]) -> list[dict[str, object]]:
    """One diagnostic per rule a dry run could not compile, from its preview payloads.

    ``path`` is workspace-relative, like every diagnostic's; ``file_path``
    stays absolute.
    """
    from pathlib import Path

    from opentide.core.root import get_repo_root

    root = get_repo_root()
    diagnostics: list[dict[str, object]] = []
    for platform, previews in payloads.items():
        for preview in previews:
            if preview.get("status") != "failed":
                continue
            source = preview.get("file")
            path = None
            if isinstance(source, str):
                try:
                    path = Path(source).resolve().relative_to(root.resolve()).as_posix()
                except (OSError, ValueError):
                    path = None  # outside the workspace: only file_path says where
            diagnostics.append(
                {
                    "code": preview.get("code") or "compile_failed",
                    "severity": "error",
                    "message": preview.get("error"),
                    "help": preview.get("help"),
                    "path": path,
                    "file_path": source,
                    "platform": platform,
                    "uuid": preview.get("uuid"),
                    "name": preview.get("name"),
                }
            )
    return diagnostics


def _nothing_to_deploy(message: str, *, dry_run: bool, **fields: object) -> dict[str, object]:
    """A skipped deploy, in the same envelope as one that planned rules.

    Planning can record a per-rule failure and still leave nothing to deploy,
    for instance when ``make_deploy_plan`` refuses a rule with
    ``external_id_in_rule``. That run failed: it is reported as such, not as a
    clean skip.
    """
    from opentide.cli.exit_codes import deployment_outcome

    outcome = deployment_outcome()
    result: dict[str, object] = {
        **fields,
        "status": "failed" if outcome.failed else "skipped",
        "message": f"{message}; planning reported rule errors" if outcome.failed else message,
        "deployed": [],
        "dry_run": dry_run,
        "plan": {},
    }
    if outcome.failed:
        result["_exit_code"] = outcome.exit_code
    if dry_run:
        result["payloads"] = {}
    return result


def keeps_deprecated(all_files: bool, requested: bool | None) -> bool:
    """Whether a deploy keeps rules whose status strategy is DISABLEMENT or DELETION.

    A ``RELEASE`` run disables a changed ``DISABLEMENT`` rule and deletes a
    changed ``DELETION`` rule: that is how setting a rule to a status such as
    the default ``DISABLED`` or ``REMOVED`` reaches the platform (#548). A
    run over every rule file (``--all``) leaves them out unless
    ``--keep-deprecated`` says otherwise, so a full redeploy does not disable
    or delete the whole retired catalogue by accident.
    """
    if requested is not None:
        return requested
    return not all_files


def resolve_run_strategies(values: Iterable[str]) -> RunStrategies:
    """Parse ``--strategy`` values, answering a status name with its strategy.

    Raises ``ValueError`` with the message the CLI prints.
    """
    from opentide.core.registry import Opentide
    from opentide.models.deployment_enums import parse_strategies

    statuses: dict[str, Any] = {}
    try:
        for status in Opentide.Configurations.Deployment.statuses:
            statuses[str(status.name).upper()] = status.strategy
    except Exception:
        statuses = {}
    return parse_strategies(values, statuses=statuses)


def strategy_suggestion(values: Any) -> str | None:
    """The deployable strategy closest to the first ``--strategy`` value that is not one."""
    from opentide.models.deployment_enums import DEPLOYABLE_STRATEGIES

    names = [strategy.name for strategy in DEPLOYABLE_STRATEGIES]
    for raw in values:
        for part in str(raw).split(","):
            value = part.strip()
            if value and value.upper() not in names:
                return did_you_mean(value, names)
    return None


def removed_plan_error() -> str | None:
    """The refusal for a run that still sets ``DEPLOYMENT_PLAN``, or ``None``."""
    from opentide.models.deployment_enums import REMOVED_PLAN_ENV, removed_plan_message

    value = os.environ.get(REMOVED_PLAN_ENV)
    if value is None or not value.strip():
        return None
    return removed_plan_message(value)


def run_deploy(
    ctx: CliContext,
    *,
    strategies: list[str] | tuple[str, ...] = (),
    all_files: bool = False,
    platform: DetectionPlatform | None = None,
    dry_run: bool = False,
    skip_promotion: bool = False,
    keep_deprecated: bool | None = None,
    wide: bool = False,
    skip_unconfigured: bool = False,
    persist_state_externally: bool = False,
) -> dict[str, object]:
    """Deploy the rules the run changed whose status maps to a run strategy.

    *strategies* are ``--strategy`` values (``PREVIEW``, ``RELEASE``). The
    rule files are those the run's diff changed (the pull or merge request,
    the push, or outside CI the last commit), or every rule file with
    *all_files*. Each rule reaches the tenants that accept a run strategy that
    deploys it. *keep_deprecated* ``None`` keeps ``DISABLEMENT`` and
    ``DELETION`` rules unless *all_files*; see :func:`keeps_deprecated`.
    *persist_state_externally* lets a CI run other than a ``RELEASE`` push
    create rules whose ids land in deployment state; the caller commits the
    shards.
    """
    from opentide.deployment.external_ids import PERSIST_EXTERNALLY_ENV

    # Per run: a long-lived process must not inherit it.
    if persist_state_externally:
        os.environ[PERSIST_EXTERNALLY_ENV] = "1"
    else:
        os.environ.pop(PERSIST_EXTERNALLY_ENV, None)
    from contextlib import nullcontext

    from opentide.core.environment import defer_missing_envvars

    plan_warnings: list[str] = []
    # Nothing live runs in a dry run: an unset credential is what a real deploy
    # would need, said once as a warning, not an error.
    unset: list[str]
    with defer_missing_envvars() if dry_run else nullcontext([]) as unset:
        result = _deploy(
            ctx,
            plan_warnings,
            strategies=strategies,
            all_files=all_files,
            platform=platform,
            dry_run=dry_run,
            skip_promotion=skip_promotion,
            keep_deprecated=keep_deprecated,
            wide=wide,
            skip_unconfigured=skip_unconfigured,
        )
    if unset:
        plan_warnings.append(unset_variables_warning(unset))
    if plan_warnings:
        result["warnings"] = [*plan_warnings, *cast(list[str], result.get("warnings", []))]
    return result


#: The CLI's answer when ``--strategy`` is missing.
STRATEGY_REQUIRED = (
    "Pass --strategy: PREVIEW deploys the rules whose status maps to PREVIEW (the pull or "
    "merge request job), RELEASE deploys and retires the rules whose status maps to RELEASE, "
    "DISABLEMENT or DELETION (the default-branch job). Rules whose status maps to UNIVERSAL "
    "are deployed by both. See 'opentide deploy --help'."
)


def _deploy(
    ctx: CliContext,
    plan_warnings: list[str],
    *,
    strategies: list[str] | tuple[str, ...],
    all_files: bool,
    platform: DetectionPlatform | None,
    dry_run: bool,
    skip_promotion: bool,
    keep_deprecated: bool | None,
    wide: bool,
    skip_unconfigured: bool = False,
) -> dict[str, object]:
    ctx.apply_environment()
    os.environ["INDEX_OUTPUT"] = "cache"
    # Each deploy grades itself. A long-lived process (MCP server, tests) must
    # not inherit a previous run's failure or warning.
    for flag in ("DEPLOYMENT_ERROR_RAISED", "DEPLOYMENT_WARNING_RAISED"):
        os.environ.pop(flag, None)
    removed = removed_plan_error()
    if removed is not None:
        return {
            "status": "failed",
            "message": removed,
            "_exit_code": 2,
            "_failure_code": USAGE_INVALID_VALUE,
        }
    if not strategies:
        return {
            "status": "failed",
            "message": STRATEGY_REQUIRED,
            "_exit_code": 2,
            "_failure_code": USAGE_MISSING_OPTION,
            "_failure_argument": "--strategy",
        }
    from opentide.core.registry import Opentide
    from opentide.deployment import CIEnvironment, make_deploy_plan, modified_mdr_files
    from opentide.deployment.ci import is_change_request
    from opentide.deployment.git_repo import MissingGitCheckout, missing_checkout_message
    from opentide.models.deployment_enums import StatusStrategy
    from opentide.mutation.promotion import PromoteMDR
    from opentide.platforms.plugins import DeployTide

    Opentide.reload()
    try:
        run = resolve_run_strategies(strategies)
    except ValueError as exc:
        return {
            "status": "failed",
            "message": str(exc),
            "_exit_code": 2,
            "_failure_code": USAGE_INVALID_CHOICE,
            "_failure_argument": "--strategy",
            "_failure_suggestion": strategy_suggestion(strategies),
        }
    try:
        environment = CIEnvironment().environment
        local_debug = environment is CIEnvironment.CIPlatforms.LocalDebug
        if (
            StatusStrategy.RELEASE in run
            and not all_files
            and not skip_promotion
            and not dry_run
            and not local_debug
            and not is_change_request(environment)
        ):
            from opentide.cli.ui.progress import Checklist

            pre_deployment = modified_mdr_files()
            with (
                Checklist(total=1) as checklist,
                checklist.step("status promotion", unit="rule") as step,
            ):
                step.done(len(pre_deployment))
                PromoteMDR().promote(pre_deployment)
        deployment_list = make_deploy_plan(
            run,
            wide_scope=wide,
            keep_deprecated=keeps_deprecated(all_files, keep_deprecated),
            warnings=plan_warnings,
            all_files=all_files,
        )
    except MissingGitCheckout as exc:
        return {
            "status": "failed",
            "message": missing_checkout_message(exc.searched),
            "_exit_code": 1,
        }
    except Exception as exc:
        message = str(exc).strip() or (f"{type(exc).__name__} while selecting the rules to deploy")
        return {"status": "failed", "message": message, "_exit_code": 1}
    if platform is not None:
        platform_key = platform.value
        if platform_key not in deployment_list:
            return _nothing_to_deploy(
                "No rules to deploy for this platform", dry_run=dry_run, platform=platform_key
            )
        deployment_list = {platform_key: deployment_list[platform_key]}
    if len(deployment_list) == 0:
        environment = CIEnvironment().environment
        if environment is CIEnvironment.CIPlatforms.GitHubActions and not ctx.json_output:
            # GitHub only parses workflow commands from stdout, and never wrapped.
            get_stdout_console().print(
                f"::warning::{_NO_RULES_MATCHED}",
                markup=False,
                highlight=False,
                soft_wrap=True,
            )
        return _nothing_to_deploy(_NO_RULES_MATCHED, dry_run=dry_run)
    deployed: list[str] = []
    plan_payload: dict[str, list[str]] = {
        system: list(uuids) for system, uuids in deployment_list.items()
    }
    from opentide.platforms.enabled import MissingTenantsError, systems_without_tenants

    tenantless = [
        MissingTenantsError(system) for system in systems_without_tenants(deployment_list)
    ]
    missing_tenants = {error.system: error.config_path for error in tenantless}
    tenants_advice = "; ".join(error.advice for error in tenantless)
    if tenantless and not dry_run:
        from opentide.cli.exit_codes import deployment_outcome

        detail = "; ".join(str(error) for error in tenantless)
        # --skip-unconfigured excuses missing tenants, not a rule that planning
        # refused (for example external_id_in_rule): that run still fails.
        refused = deployment_outcome().failed
        if skip_unconfigured and len(tenantless) == len(deployment_list) and not refused:
            return {
                "status": "skipped",
                "message": f"Skipped deploy: {detail}",
                "advice": tenants_advice,
                "missing_tenants": missing_tenants,
                "deployed": deployed,
                "dry_run": False,
                "plan": plan_payload,
            }
        return {
            "status": "failed",
            "message": (
                f"Planning refused rules; {detail}" if refused else f"Cannot deploy: {detail}"
            ),
            "advice": tenants_advice,
            "missing_tenants": missing_tenants,
            "deployed": deployed,
            "dry_run": False,
            "plan": plan_payload,
            "_exit_code": 1,
        }
    IndexManager.reload()
    try:
        mdr_deployers = cast(dict[str, Any], DeployTide().mdr_for(deployment_list))
    except Exception as exc:
        message = str(exc).strip() or f"{type(exc).__name__} while loading deployment engines"
        return {"status": "failed", "message": message, "deployed": deployed, "_exit_code": 1}
    payloads: dict[str, list[dict[str, object]]] = {}
    # Resolve every platform's tenants before anything is sent. A platform
    # file that still sets the removed tenant `deployment` key raises
    # ValueError here, so the run fails with the replacement line instead of
    # crashing inside the first deployer after others already ran.
    targets: dict[str, dict[str, list[str]]] = {}
    for system, uuids in deployment_list.items():
        if system in missing_tenants:
            continue
        try:
            targets[system] = _tenant_targets(system, uuids, run, wide)
        except ValueError as exc:
            return {
                "status": "failed",
                "message": str(exc),
                "deployed": deployed,
                "dry_run": dry_run,
                "plan": plan_payload,
                "_exit_code": 1,
            }
        except Exception as exc:
            logger.warning("tenant_targets_failed", system=system, detail=str(exc))
    from opentide.cli.services.deploy_plan import (
        deployed_message,
        plan_changes,
        plan_message,
        plan_summary,
    )
    from opentide.cli.ui.progress import Checklist, plural

    # Planned before anything is sent: a create records an id, which would
    # make the same rule read as an update afterwards.
    changes = plan_changes(deployment_list, targets)
    started = time.perf_counter()
    for system in deployment_list:
        if system not in mdr_deployers:
            return {
                "status": "failed",
                "message": f"Cannot find a deployment engine for {system}",
                "deployed": deployed,
                "_exit_code": 1,
            }
    with Checklist(total=len(deployment_list)) as checklist:
        for system, uuids in deployment_list.items():
            deployer = cast(Any, mdr_deployers[system])
            if dry_run:
                logger.info(
                    "event", detail=f"Dry-run: would deploy {len(uuids)} rule(s) to {system}"
                )
                from opentide.deployment.preview import preview_platform_deployment

                payloads[system] = preview_platform_deployment(system, uuids)
                if system not in missing_tenants:
                    deployed.append(system)
                continue
            with checklist.step(system, unit="rule") as step:
                step.done(len(uuids))
                # A deployer reports a failed rule through the environment, not
                # an exception; the step must not read as done.
                failed_before = os.environ.get("DEPLOYMENT_ERROR_RAISED")
                try:
                    if wide:
                        from opentide.deployment.planning import wide_scope

                        with wide_scope():
                            deployer.deploy(mdr_deployment=uuids, strategies=run)
                    else:
                        deployer.deploy(mdr_deployment=uuids, strategies=run)
                except Exception as exc:
                    # A TypeError used to be retried as the pre-strategy signature
                    # `deploy(deployment=...)`, which no engine has: its own TypeError
                    # replaced the real one. Any other error escaped as a traceback,
                    # with no result and no record of the platforms already deployed.
                    detail = str(exc).strip()
                    error = f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__
                    logger.error("platform_deployment_failed", system=system, detail=error)
                    step.status = "failed"
                    return {
                        "status": "failed",
                        "message": f"Deployment to {system} failed: {error}",
                        "deployed": deployed,
                        "dry_run": dry_run,
                        "plan": plan_payload,
                        "strategies": [strategy.name for strategy in run],
                        "_exit_code": 1,
                    }
                if os.environ.get("DEPLOYMENT_ERROR_RAISED") and not failed_before:
                    step.status = "failed"
            deployed.append(system)
    from opentide.cli.exit_codes import deployment_outcome

    outcome = deployment_outcome()
    tenant_count = sum(len(tenants) for tenants in targets.values())
    if dry_run:
        message = plan_message(changes)
    elif outcome.failed:
        message = "Deployment finished with errors"
    else:
        reached = [change for change in changes if change.platform in deployed]
        message = deployed_message(reached, time.perf_counter() - started)
    result: dict[str, object] = {
        "message": message,
        "status": "failed" if outcome.failed else "completed",
        "deployed": deployed,
        "dry_run": dry_run,
        "plan": plan_payload,
        "changes": [change.to_dict() for change in changes],
        "_summary": plan_summary(changes, list(deployment_list), tenant_count),
        "_exit_code": outcome.exit_code,
    }
    if dry_run:
        # The tally is a plan even when a rule would fail: the diagnostics say
        # so above it, and the exit code carries the failure.
        result["_outcome_kind"] = "plan"
        diagnostics = compile_diagnostics(payloads)
        if diagnostics:
            result["diagnostics"] = diagnostics
            result["error"] = f"{plural(len(diagnostics), 'rule')} would fail to deploy"
    warnings = [f"{error}, so a real deploy would stop" for error in tenantless]
    if outcome.warned:
        warnings.append("Some rules reported deployment warnings")
    if warnings:
        result["warnings"] = warnings
    result["strategies"] = [strategy.name for strategy in run]
    if dry_run:
        result["payloads"] = payloads
        result["tenants"] = targets
        if missing_tenants:
            result["missing_tenants"] = missing_tenants
            result["advice"] = tenants_advice
    return result
