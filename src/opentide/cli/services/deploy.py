"""Deployment services for the CLI."""

from __future__ import annotations

import os
import time
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, cast

import structlog

from opentide.cli.enums import DetectionPlatform
from opentide.cli.ui.contract import (
    ISSUES_FOUND,
    USAGE_INVALID_CHOICE,
    USAGE_INVALID_VALUE,
    USAGE_MISSING_OPTION,
    did_you_mean,
)
from opentide.cli.ui.glyphs import glyph
from opentide.core.errors import UserFileError
from opentide.core.index_manager import IndexManager

logger = structlog.get_logger("opentide.cli.services.deploy")
if TYPE_CHECKING:
    from opentide.cli.context import CliContext
    from opentide.cli.ui.progress import Checklist
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


#: Beyond this many unset variables the warning names the first ones and counts the rest.
UNSET_SHOWN = 3


def unset_variables_warning(names: list[str]) -> str:
    """``a real deploy would need $A and $B, which are unset``.

    Four platforms' tenants made it one sentence of 13 names that the terminal
    broke mid-name (post-merge end-to-end run); past :data:`UNSET_SHOWN` it
    counts the rest and points at ``opentide doctor``, which lists them by tenant.
    """
    shown = [f"${name}" for name in names]
    if len(shown) > UNSET_SHOWN:
        rest = len(shown) - UNSET_SHOWN
        return (
            f"a real deploy would need {len(shown)} variables that are unset: "
            f"{', '.join(shown[:UNSET_SHOWN])} and {rest} more; opentide doctor lists "
            "them by tenant"
        )
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
    from opentide.registry.builder import parse_errors_reported_by_caller

    plan_warnings: list[str] = []
    # Blocks whose status no run strategy deploys: counted, not logged per rule.
    plan_skipped: list[dict[str, str]] = []
    # Nothing live runs in a dry run: an unset credential is what a real deploy
    # would need, said once as a warning, not an error.
    unset: list[str]
    # Deploy reports the object files the registry could not read: a rule it
    # reads is one frame (ObjectFileError), any other file one warning, never
    # also a log line for the same file.
    with (
        parse_errors_reported_by_caller() as unreadable,
        defer_missing_envvars() if dry_run else nullcontext([]) as unset,
    ):
        try:
            result = _deploy(
                ctx,
                plan_warnings,
                plan_skipped,
                strategies=strategies,
                all_files=all_files,
                platform=platform,
                dry_run=dry_run,
                skip_promotion=skip_promotion,
                keep_deprecated=keep_deprecated,
                wide=wide,
                skip_unconfigured=skip_unconfigured,
            )
        except UserFileError as error:
            for path, problem in _unread_object_files(unreadable, exclude=error.path):
                logger.error("malformed_object_yaml", path=path, error=problem)
            raise
    unread = _unread_object_files(unreadable)
    if unread:
        plan_warnings.append(_unread_warning(unread))
    if unset:
        plan_warnings.append(unset_variables_warning(unset))
    if plan_warnings:
        result["warnings"] = [*plan_warnings, *cast(list[str], result.get("warnings", []))]
    if plan_skipped:
        _report_skipped(result, plan_skipped)
    if result.get("status") == "skipped" and not result.get("_next_actions"):
        from opentide.cli.ui.contract import NO_WORKSPACE_STEP
        from opentide.core.root import get_repo_root, is_workspace_root

        if not is_workspace_root(get_repo_root()):
            result["_next_actions"] = [NO_WORKSPACE_STEP]
    return result


def _report_skipped(result: dict[str, object], skipped: list[dict[str, str]]) -> None:
    """Count the blocks a status kept out of the plan, and say which statuses deploy.

    They used to print as one ``warning: Rule skipped for strategy · system: …``
    log line per block, and a run that skipped them all ended on
    ``Skipped: No rule this run read has a status that maps to its strategies``.
    """
    from collections import Counter

    from opentide.cli.ui.glyphs import glyph
    from opentide.cli.ui.progress import plural
    from opentide.deployment.utils import statuses_deployed_by
    from opentide.models.deployment_enums import StatusStrategy

    rules = len({entry["uuid"] for entry in skipped})
    statuses = Counter(entry["status"] for entry in skipped)
    if len(statuses) == 1:
        in_status = f"{plural(rules, 'rule')} in {next(iter(statuses))}"
    else:
        listed = ", ".join(f"{count} in {status}" for status, count in statuses.most_common())
        in_status = f"{plural(rules, 'rule')} left out: {listed}"
    names = cast(list[str], result.get("strategies") or [])
    run = tuple(StatusStrategy[name] for name in names if name in StatusStrategy.__members__)
    run_names = " or ".join(strategy.name for strategy in run) or "this run"
    result["skipped"] = skipped
    summary = cast(dict[str, object], result.get("_summary") or {})
    result["_summary"] = {**summary, "skipped": rules}
    deployable = statuses_deployed_by(run) if run else []
    if len(deployable) > 1:
        listed = ", ".join(deployable[:-1]) + f" or {deployable[-1]}"
    else:
        listed = deployable[0] if deployable else ""
    advice = (
        f"set a platform block's status to {listed} for {run_names} to deploy it"
        if listed
        else f"no configured status deploys with {run_names}"
    )
    if result.get("status") == "skipped" and not result.get("plan"):
        result["_outcome"] = (
            f"No rule has a status {run_names} deploys {glyph('separator')} {in_status}"
        )
        result.setdefault("advice", advice)
    else:
        result.setdefault("detail", f"not in the plan: {in_status}; {advice}")


def _unread_object_files(
    entries: list[dict[str, str]], exclude: object = None
) -> list[tuple[str, str]]:
    """``(path, problem)`` for each object file the registry could not read this run.

    *entries* come from ``parse_errors_reported_by_caller()``. Paths are shown
    as :func:`_shown` gives them. *exclude* is a file already reported as a frame.
    """
    from pathlib import Path

    skipped = None if exclude is None else Path(str(exclude)).resolve()
    unread: list[tuple[str, str]] = []
    for entry in entries:
        path = Path(entry["path"])
        if skipped is not None and path.resolve() == skipped:
            continue
        unread.append((_shown(path), entry["error"]))
    return unread


def _shown(path: object) -> str:
    """Relative to the current directory when inside it, else to the workspace."""
    from pathlib import Path

    from opentide.core.root import get_repo_root

    resolved = Path(str(path)).resolve()
    for base in (Path.cwd(), get_repo_root()):
        try:
            return resolved.relative_to(Path(base).resolve()).as_posix()
        except (OSError, ValueError):
            continue
    return str(path)


def _unread_warning(unread: list[tuple[str, str]]) -> str:
    files = ", ".join(path for path, _ in unread)
    noun = "object file" if len(unread) == 1 else "object files"
    return f"{len(unread)} {noun} could not be read: {files}; opentide validate shows where"


#: The CLI's answer when ``--strategy`` is missing.
STRATEGY_REQUIRED = (
    "Pass --strategy: PREVIEW deploys the rules whose status maps to PREVIEW (the pull or "
    "merge request job), RELEASE deploys and retires the rules whose status maps to RELEASE, "
    "DISABLEMENT or DELETION (the default-branch job). Rules whose status maps to UNIVERSAL "
    "are deployed by both. See 'opentide deploy --help'."
)


def _announce_plan(checklist: Checklist, *, strategies: list[str], scope: str, tally: str) -> None:
    """The header and tally a real run prints before it sends anything.

    A dry run prints the whole plan; a real run lists each rule as it is sent,
    so this is only the header and the tally the run is about to make true.
    """
    from rich.text import Text

    separator = f" {glyph('separator', encoding=checklist.console.encoding or 'utf-8')} "
    header = Text("Deploy plan", style="bold")
    header.append(separator + "strategy ", style="dim")
    header.append(" ".join(strategies), style="bold")
    header.append(separator + scope, style="dim")
    checklist.line(header)
    checklist.line(Text(tally, style="dim"))


def _deploy(
    ctx: CliContext,
    plan_warnings: list[str],
    plan_skipped: list[dict[str, str]],
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
            skipped=plan_skipped,
        )
    except MissingGitCheckout as exc:
        return {
            "status": "failed",
            "message": missing_checkout_message(exc.searched),
            "_exit_code": 1,
        }
    except UserFileError:
        raise  # the CLI points at the file
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
        if not ctx.json_output:
            from opentide.cli.ui.ci import emit_warning

            # A run-level annotation on GitHub and Azure; nothing elsewhere.
            emit_warning(_NO_RULES_MATCHED)
        return _nothing_to_deploy(
            _NO_RULES_MATCHED, dry_run=dry_run, strategies=[strategy.name for strategy in run]
        )
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
        mark_failures,
        outcome_message,
        plan_changes,
        plan_message,
        plan_scope,
        plan_summary,
        run_summary,
    )
    from opentide.cli.ui.deploy_log import NOT_ATTEMPTED, DeployLog, counts_text
    from opentide.cli.ui.progress import Checklist, plural
    from opentide.core import deploy_events

    # Planned before anything is sent: a create records an id, which would
    # make the same rule read as an update afterwards.
    changes = plan_changes(deployment_list, targets)
    tenant_count = sum(len(tenants) for tenants in targets.values())
    started = time.perf_counter()
    for system in deployment_list:
        if system not in mdr_deployers:
            return {
                "status": "failed",
                "message": f"Cannot find a deployment engine for {system}",
                "deployed": deployed,
                "_exit_code": 1,
            }
    run_log: DeployLog | None = None
    failure: tuple[str, Exception] | None = None
    with Checklist(total=len(deployment_list)) as checklist:
        if not dry_run:
            run_log = DeployLog(checklist, changes)
            _announce_plan(
                checklist,
                strategies=[strategy.name for strategy in run],
                scope=plan_scope(len(deployment_list), tenant_count),
                tally=plan_message(changes),
            )
        for system, uuids in deployment_list.items():
            deployer = cast(Any, mdr_deployers[system])
            if run_log is None:  # a dry run: nothing is sent, so nothing reports
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
                    with deploy_events.listen(run_log):
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
                    failure = (system, exc)
                    step.status = "failed"
                    # Every rule the run never reached, on this platform and the next.
                    run_log.unreached()
                    step.done(outcome=counts_text(run_log.platform_results(system)))
                else:
                    run_log.settle(system)
                    mine = run_log.platform_results(system)
                    step.done(outcome=counts_text(mine))
                    if any(result.status == "failed" for result in mine) or (
                        os.environ.get("DEPLOYMENT_ERROR_RAISED") and not failed_before
                    ):
                        step.status = "failed"
            if failure is not None:
                break
            deployed.append(system)
        if failure is not None:
            for rest in list(deployment_list)[list(deployment_list).index(failure[0]) + 1 :]:
                with checklist.step(rest, unit="rule") as step:
                    step.skip(NOT_ATTEMPTED)
    results = run_log.results if run_log is not None else []
    seconds = time.perf_counter() - started
    if failure is not None and run_log is not None:
        system, exc = failure
        # An error on a rule is on that rule's line already; an error before any
        # rule of this platform (the tenant's credentials, say) has no line, so it is
        # logged. A rule another platform failed without raising is not this one's.
        culprit = next(
            (result for result in run_log.platform_results(system) if result.status == "failed"),
            None,
        )
        detail = str(exc).strip()
        error = f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__
        failed_result: dict[str, object] = {
            "status": "failed",
            "message": f"Deployment to {system} failed: {error}",
            "deployed": deployed,
            "dry_run": dry_run,
            "plan": plan_payload,
            "strategies": [strategy.name for strategy in run],
            "changes": [change.to_dict() for change in changes],
            "results": [result.to_dict() for result in results],
            "_summary": run_summary(results, list(deployment_list), tenant_count, seconds),
            "_exit_code": 1,
        }
        if culprit is not None:
            logger.debug("platform_deployment_failed", system=system, detail=error)
            failed_result["message"] = outcome_message(results, seconds, failed=True)
            failed_result["error"] = (
                f"Deployment to {system} failed on {culprit.name}: {culprit.error}"
            )
            failed_result["_failure_code"] = ISSUES_FOUND
        else:
            logger.error("platform_deployment_failed", system=system, detail=error)
        return failed_result
    from opentide.cli.exit_codes import deployment_outcome

    outcome = deployment_outcome()
    diagnostics = compile_diagnostics(payloads) if dry_run else []
    if diagnostics:
        # A rule that would fail is not a "create or update" (post-merge run).
        failing = {(str(item["platform"]), str(item["uuid"])) for item in diagnostics}
        changes = mark_failures(changes, failing)
    if dry_run:
        message = plan_message(changes)
    elif outcome.failed and not any(result.status == "failed" for result in results):
        message = "Deployment finished with errors"
    else:
        message = outcome_message(results, seconds, failed=outcome.failed)
    result: dict[str, object] = {
        "message": message,
        "status": "failed" if outcome.failed else "completed",
        "deployed": deployed,
        "dry_run": dry_run,
        "plan": plan_payload,
        "changes": [change.to_dict() for change in changes],
        "_summary": (
            plan_summary(changes, list(deployment_list), tenant_count)
            if dry_run
            else run_summary(results, list(deployment_list), tenant_count, seconds)
        ),
        "_exit_code": outcome.exit_code,
    }
    if not dry_run:
        result["results"] = [item.to_dict() for item in results]
        if outcome.failed and any(item.status == "failed" for item in results):
            result["_failure_code"] = ISSUES_FOUND
    if dry_run:
        # The tally is a plan even when a rule would fail: the diagnostics say
        # so above it, and the exit code carries the failure.
        result["_outcome_kind"] = "plan"
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
