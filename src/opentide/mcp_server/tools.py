"""MCP tool implementations."""

from __future__ import annotations

import os
import shlex
from typing import Any

from opentide.core.registry import Opentide
from opentide.mcp_server.catalog import (
    coverage_analysis,
    ensure_initialised,
    get_chaining_graph,
    search_catalog,
)
from opentide.mcp_server.constants import MAX_QUERY_ROWS, QUERY_VALIDATION_PLATFORMS


def tool_search(
    query: str,
    type: str = "",
    platform: str = "",
    status: str = "",
    technique: str = "",
    actor: str = "",
) -> list[dict[str, Any]]:
    return search_catalog(
        query, object_type=type, platform=platform, status=status, technique=technique, actor=actor
    )


def tool_get_chaining(uuid: str) -> dict[str, Any]:
    return get_chaining_graph(uuid)


def tool_coverage(technique: str = "", tactic: str = "") -> dict[str, Any]:
    return coverage_analysis(technique=technique, tactic=tactic)


def next_action(
    tool: str, arguments: dict[str, Any], *, command: str, reason: str
) -> dict[str, Any]:
    """A tool call worth making next: the CLI's ``{command, reason}`` plus the MCP call.

    ``command`` is the same step as an ``opentide`` command line, for an
    agent that has a shell rather than this server.
    """
    return {"tool": tool, "arguments": arguments, "command": command, "reason": reason}


def _annotate(payload: dict[str, Any], report: Any, buckets: tuple[str, ...]) -> list[Any]:
    """Add the CLI's diagnostic fields to each dumped issue; the issues keep every key."""
    from opentide.cli.ui.diagnostics import annotate_report
    from opentide.registry.discovery import discover_workspace

    return annotate_report(payload, report, workspace=discover_workspace(), buckets=buckets)


def _validation_next_actions(
    diagnostics: list[Any], *, again: dict[str, Any]
) -> list[dict[str, Any]]:
    """Explain the first error's code, then validate again once the fixes are written.

    One ``explain`` (each issue's own ``explain`` field names the rest) and the
    re-run: within the three next steps a CLI result prints. When a fix is
    safe, the re-run's command is ``opentide --json validate --fix …``, which
    writes the safe fixes and validates again in one step (#646); the MCP call
    stays the report, for an agent that applies the edits itself.
    """
    first = next((item.code for item in diagnostics if item.severity == "error"), None)
    if first is None:
        return []
    explain = next_action(
        "explain",
        {"code": first},
        command=f"opentide explain {first}",
        reason=f"what {first} means and how to fix it",
    )
    rerun = {**again, "reason": "validate again after fixing the issues"}
    if any(item.fix is not None and item.fix.safe for item in diagnostics):
        prefix = "opentide --json validate"
        command = str(again["command"])
        if command.startswith(prefix):
            command = f"{prefix} --fix{command[len(prefix) :]}"
        rerun.update(command=command, reason="apply the safe fixes, then validate again")
    elif any(item.fix is not None for item in diagnostics):
        rerun["reason"] = "validate again after applying the fix edits"
    return [explain, rerun]


def _rule_platforms(uuid: str) -> list[str]:
    """Platforms the rule has a configuration block for, that this install knows."""
    body = Opentide.Models.rules.get(uuid)
    if body is not None and not isinstance(body, dict):
        body = body.model_dump(by_alias=True) if hasattr(body, "model_dump") else {}
    configs = (body or {}).get("configurations") or {}
    if not isinstance(configs, dict):
        return []
    return [name for name in configs if name in Opentide.Platforms]


def _run_strategies(rule: Any, platform: str) -> list[str]:
    """The ``--strategy`` values whose run deploys *rule* to *platform*; none for ``INERT``.

    The status is the platform block's, as a real deploy reads it. A status
    the deployment configuration does not define falls back to ``PREVIEW``,
    so the command still runs.
    """
    from opentide.deployment.utils import check_status
    from opentide.models.deployment_enums import deployed_by

    block = getattr(getattr(rule, "configurations", None), platform, None)
    status = str(getattr(block, "status", None) or getattr(rule, "status", ""))
    defined = {item.name for item in Opentide.Configurations.Deployment.statuses}
    if status not in defined:
        return ["PREVIEW"]
    try:
        rule_strategy = check_status(status)
    except (KeyError, TypeError, ValueError):
        return ["PREVIEW"]
    return [strategy.name for strategy in deployed_by(rule_strategy)]


def tool_validate_rule(uuid: str) -> dict[str, Any]:
    # The server outlives any edit an agent makes; validating the index built at
    # start-up would report the content the author has already changed.
    Opentide.reload()
    from opentide.validation.scope import ValidationScope
    from opentide.validation.session import run_validation

    # The raw index, not ``Opentide.Rules``: typed loading raises for the whole
    # catalogue when one rule does not load, which is what validation reports.
    if uuid not in Opentide.Models.rules:
        return {
            "valid": False,
            "errors": [f"Rule {uuid} not found"],
            "warnings": [],
            "issues": [],
            "next_actions": [
                next_action(
                    "search",
                    {"query": "", "type": "rule"},
                    command="opentide --json info rules",
                    reason=(
                        "list the catalogue's rules to find the UUID: search returns "
                        "each rule's title, the command only the UUIDs"
                    ),
                )
            ],
        }
    report = run_validation(scope=ValidationScope.narrow(uuids=frozenset({uuid})))
    dumped = report.model_dump_json_ready()
    diagnostics = _annotate(dumped, report, ("issues",))
    again = next_action(
        "validate_rule",
        {"uuid": uuid},
        command=f"opentide --json validate --uuid {shlex.quote(uuid)}",
        reason="",
    )
    actions = _validation_next_actions(diagnostics, again=again)
    if report.ok:
        try:
            rule = Opentide.Rules.get(uuid)
        except Exception:
            # Typed loading fails for the whole catalogue when another rule
            # does not load; the status then falls back to PREVIEW.
            rule = None
        for platform in _rule_platforms(uuid):
            strategies = _run_strategies(rule, platform)
            if not strategies:
                continue  # INERT: no run deploys it
            flags = " ".join(f"--strategy {name}" for name in strategies)
            actions.append(
                next_action(
                    "deploy_rule",
                    {"uuid": uuid, "platform": platform, "dry_run": True},
                    # The CLI has no --uuid: --all previews every rule these
                    # strategies deploy, this one among them.
                    command=(
                        f"opentide --json deploy --dry-run {flags} --all --platform {platform}"
                    ),
                    reason=f"preview the {platform} deployment; nothing is sent",
                )
            )
    return {
        "valid": report.ok,
        "errors": [issue.to_legacy_string() for issue in report.errors],
        "warnings": [issue.to_legacy_string() for issue in report.warnings],
        "issues": dumped.get("issues", []),
        "next_actions": actions,
    }


def tool_validation_report(
    *,
    file: str | None = None,
    uuid: str | None = None,
    object_type: str | None = None,
    queries: str = "error",
) -> dict[str, Any]:
    """Structured validation report for agents (headless API).

    *queries* is ``validate --queries``: ``error``, ``warn`` or ``off``.
    """
    from opentide.cli.enums import QueriesMode
    from opentide.cli.services.validation import default_check_names, queries_flag

    try:
        mode = QueriesMode(queries)
    except ValueError:
        choices = ", ".join(item.value for item in QueriesMode)
        return {"ok": False, "error": f"queries must be one of {choices}, got {queries!r}"}
    # Re-read the workspace, as ``tool_validate_rule`` does.
    Opentide.reload()
    from opentide.validation.checks.kinds import ValidateCheck
    from opentide.validation.scope import ValidationScope
    from opentide.validation.session import run_validation

    scope = ValidationScope.full()
    if file or uuid or object_type:
        scope = ValidationScope.narrow(
            files=frozenset({file}) if file else None,
            uuids=frozenset({uuid}) if uuid else None,
            types=frozenset({object_type}) if object_type else None,
        )
    report = run_validation(
        scope=scope,
        checks=frozenset(ValidateCheck(name) for name in default_check_names(mode)),
        queries_as_warnings=mode is QueriesMode.warn,
    )
    payload = report.model_dump_json_ready()
    diagnostics = _annotate(payload, report, ("issues", "warnings"))
    arguments = {
        key: value
        for key, value in (("file", file), ("uuid", uuid), ("object_type", object_type))
        if value
    }
    flags = "".join(
        f" --{'type' if key == 'object_type' else key} {shlex.quote(value)}"
        for key, value in arguments.items()
    )
    flags += "".join(f" {word}" for word in queries_flag(mode))
    if mode is not QueriesMode.error:
        arguments["queries"] = mode.value
    again = next_action(
        "validation_report", arguments, command=f"opentide --json validate{flags}", reason=""
    )
    payload["next_actions"] = _validation_next_actions(diagnostics, again=again)
    return payload


def tool_explain(code: str = "") -> dict[str, Any]:
    """The ``opentide explain`` page for *code*; every code with its meaning when empty."""
    from opentide.cli.services.explain import all_pages, diagnostic_codes, load_page
    from opentide.cli.ui.contract import did_you_mean

    wanted = code.strip()
    if not wanted:
        pages = all_pages()
        return {
            "found": True,
            "codes": [{"code": page.code, "meaning": page.summary} for page in pages],
        }
    page = load_page(wanted)
    if page is None:
        return {
            "found": False,
            "code": wanted,
            "message": f"No diagnostic code {wanted!r}. Call explain with no code to list them.",
            "suggestion": did_you_mean(wanted, diagnostic_codes()),
        }
    return {"found": True, **page.to_dict()}


#: The language a platform's ``query`` is in, when the tool is not told one.
_DEFAULT_QUERY_LANGUAGE = {
    "sentinel": "kql",
    "defender_for_endpoint": "kql",
    "splunk": "spl",
    "carbon_black_cloud": "lucene",
    "elastic": "kuery",
}


def tool_validate_query(
    query: str, platform: str, live: bool = False, language: str = "", stack: str = ""
) -> dict[str, Any]:
    """Check *query* offline with the analysis engine; ``live=True`` checks the tenant.

    ``live=True`` validates the catalogue rules for ``platform``, not ``query``.
    """
    if platform not in QUERY_VALIDATION_PLATFORMS:
        return {
            "valid": None,
            "supported": False,
            "mode": "unsupported",
            "message": f"query validation not supported for {platform}",
            "errors": [],
        }
    if live:
        from opentide.cli.context import CliContext
        from opentide.cli.services.validation import validate_query_platform

        result = validate_query_platform(CliContext(), platform, live=True)
        # The CLI envelope's failure code; the tool payload keeps its shape.
        result.pop("_failure_code", None)
        return result
    return _offline_query_check(query, platform, language=language, stack=stack)


def _offline_query_check(query: str, platform: str, *, language: str, stack: str) -> dict[str, Any]:
    """``validate_query`` without ``live``: the engine checks the text it is given."""
    from opentide.analysis import (
        OFFLINE_QUERY_LANGUAGES,
        EngineUnavailableError,
        check_query,
        engine_versions,
    )
    from opentide.cli.ui.diagnostics import engine_reference, explain_command

    live_step = next_action(
        "validate_query",
        {"query": query, "platform": platform, "live": True},
        command=f"opentide --json validate query --platform {platform} --live",
        reason=(
            f"check the catalogue's {platform} rules: this contacts the {platform} tenant with "
            "the configured credentials, so ask a person first"
        ),
    )
    base: dict[str, Any] = {"supported": True, "mode": "offline", "platform": platform}
    languages = OFFLINE_QUERY_LANGUAGES.get(platform, ())
    if not languages:
        return {
            **base,
            "valid": None,
            "status": "failed",
            "message": (
                f"{platform} queries are checked on the tenant only; the engine does not parse "
                "them. Pass live: true."
            ),
            "query_preview": query[:200],
            "next_actions": [live_step],
        }
    if not query.strip():
        # Most engines accept an empty query; an empty query is not a detection.
        return {
            **base,
            "valid": None,
            "status": "failed",
            "message": "query is empty: pass the query text to check",
        }
    chosen = language.strip().lower() or _DEFAULT_QUERY_LANGUAGE[platform]
    if chosen not in languages:
        return {
            **base,
            "valid": None,
            "status": "failed",
            "message": (
                f"{platform} queries are in {', '.join(languages)}, not {chosen!r}; pass one "
                "of those as language"
            ),
        }
    try:
        findings = check_query(query, language=chosen, platform=platform, stack=stack or None)
        versions = engine_versions()
    except EngineUnavailableError as exc:
        return {
            **base,
            "valid": None,
            "status": "failed",
            "message": str(exc),
            "advice": exc.advice,
        }
    diagnostics = []
    for finding in findings:
        reference = engine_reference(finding.code)
        diagnostics.append(
            {
                "code": finding.code,
                "severity": finding.severity,
                "message": finding.message,
                "line": finding.line,
                "column": finding.column,
                "end_line": finding.end_line,
                "end_column": finding.end_column,
                "suggestion": finding.suggestion,
                "reference": None if reference is None else reference[1],
                "explain": explain_command(finding.code),
            }
        )
    errors = [item for item in diagnostics if item["severity"] == "error"]
    warnings = [item for item in diagnostics if item["severity"] == "warning"]
    payload: dict[str, Any] = {
        **base,
        "language": chosen,
        "valid": not errors,
        "status": "failed" if errors else "passed",
        "message": (
            f"{len(errors)} error(s) in the {chosen} query"
            if errors
            else f"The {chosen} query is valid offline"
            + (f", with {len(warnings)} warning(s)" if warnings else "")
        ),
        "errors": errors,
        "warnings": warnings,
        "diagnostics": diagnostics,
        "engine": versions,
        "query_preview": query[:200],
    }
    first = (errors or warnings or [None])[0]
    actions = []
    if first is not None:
        actions.append(
            next_action(
                "explain",
                {"code": first["code"]},
                command=str(first["explain"]),
                reason="how to fix it",
            )
        )
    actions.append(live_step)
    payload["next_actions"] = actions
    return payload


def tool_run_query(query: str, platform: str, tenant: str = "") -> dict[str, Any]:
    """Not implemented. Never returns a row payload that looks like a real run."""
    if platform not in QUERY_VALIDATION_PLATFORMS:
        return {
            "supported": False,
            "stub": True,
            "rows": None,
            "platform": platform,
            "tenant": tenant or None,
            "message": f"query execution not supported for {platform}",
            "query_preview": query[:200],
        }
    return {
        "supported": True,
        "stub": True,
        "rows": None,
        "platform": platform,
        "tenant": tenant or None,
        "message": (
            "Read-only query execution is not implemented; no query was sent to "
            f"{platform}. The live path would cap results at {MAX_QUERY_ROWS} rows."
        ),
        "query_preview": query[:200],
    }


def _unknown_platform(uuid: str, platform: str, *, dry_run: bool) -> dict[str, Any]:
    return {
        "action": "error",
        "tenant": None,
        "rule_id": uuid,
        "status": "unknown_platform",
        "dry_run": dry_run,
        "platform": platform,
        "message": f"Unknown platform {platform!r}",
    }


def _missing_tenants(uuid: str, platform: str) -> dict[str, Any] | None:
    from opentide.platforms.enabled import MissingTenantsError, systems_without_tenants

    if platform not in systems_without_tenants([platform]):
        return None
    error = MissingTenantsError(platform)
    return {
        "action": "error",
        "tenant": None,
        "rule_id": uuid,
        "status": "failed",
        "dry_run": False,
        "platform": platform,
        "message": f"Cannot deploy: {error}",
        "advice": error.advice,
        "missing_tenants": {error.system: error.config_path},
    }


def tool_deploy_rule(uuid: str, platform: str, dry_run: bool = True) -> dict[str, Any]:
    ensure_initialised()
    _ = Opentide.Rules
    rule = Opentide.Rules.get(uuid)
    if rule is None:
        return {
            "action": "error",
            "tenant": None,
            "rule_id": uuid,
            "status": "not_found",
            "dry_run": dry_run,
        }
    if platform not in Opentide.Platforms:
        return _unknown_platform(uuid, platform, dry_run=dry_run)
    if not dry_run:
        missing = _missing_tenants(uuid, platform)
        if missing is not None:
            return missing
    # Deployers report per-rule refusals (external_id_in_rule,
    # deployment_state_write_failed, ...) through these flags rather than by
    # raising. Each call grades itself: a long-lived server must not inherit a
    # previous call's result.
    for flag in ("DEPLOYMENT_ERROR_RAISED", "DEPLOYMENT_WARNING_RAISED"):
        os.environ.pop(flag, None)
    try:
        result = rule.deploy(platform, dry_run=dry_run)
    except ValueError as exc:
        return {
            "action": "error",
            "tenant": None,
            "rule_id": uuid,
            "status": "error",
            "dry_run": dry_run,
            "platform": platform,
            "message": str(exc),
        }
    from opentide.cli.exit_codes import deployment_outcome

    outcome = deployment_outcome()
    if outcome.failed:
        return {
            "action": "error",
            "tenant": None,
            "rule_id": uuid,
            "status": "failed",
            "dry_run": result.dry_run,
            "platform": platform,
            "message": (
                "Deployment failed: the deployer reported a rule error "
                "(see the log for its code, for example external_id_in_rule)"
            ),
            "error": "deployment_failed",
        }
    return {
        "action": "dry-run" if dry_run else "deploy",
        "tenant": None,
        "rule_id": uuid,
        "status": rule.status,
        "dry_run": result.dry_run,
        "platform": platform,
        "message": result.message,
    }


def _platform_deployment_state(
    cfg: Any, external_ids: dict[str, str] | None = None
) -> dict[str, Any]:
    """A platform counts as deployed once a vendor id is recorded or tenants are named.

    Vendor ids come from ``.opentide/states/deployment/<uuid>.json`` (RFC 0010),
    keyed by tenant. ``rule_id`` is that id when exactly one tenant is bound.
    """
    ids = dict(external_ids or {})
    tenants = (cfg.get("tenants") or []) if isinstance(cfg, dict) else []
    if not isinstance(tenants, list):
        tenants = []
    rule_id = next(iter(ids.values())) if len(ids) == 1 else None
    return {
        "deployed": bool(ids) or bool(tenants),
        "rule_id": rule_id,
        "external_ids": ids,
        "tenants": tenants,
    }


def tool_deployment_status(uuid: str) -> dict[str, Any]:
    ensure_initialised()
    body = Opentide.Models.rules.get(uuid)
    if body is None:
        return {"platforms": {}, "uuid": uuid, "found": False}
    if not isinstance(body, dict):
        body = body.model_dump(by_alias=True) if hasattr(body, "model_dump") else {}
    from opentide.states.deployment import DeploymentState, DeploymentStateError

    recorded: dict[str, dict[str, str]] = {}
    state_error: dict[str, str] | None = None
    try:
        recorded = DeploymentState.load(uuid).platforms
    except DeploymentStateError as error:
        state_error = {"code": error.code, "message": error.message}
    platforms_state: dict[str, Any] = {}
    configs = body.get("configurations", {}) or body.get("platforms", {})
    if isinstance(configs, dict):
        for name, cfg in configs.items():
            platforms_state[name] = _platform_deployment_state(cfg, recorded.get(name))
    for name, ids in recorded.items():
        platforms_state.setdefault(name, _platform_deployment_state(None, ids))
    if state_error is not None:
        return {
            "platforms": platforms_state,
            "uuid": uuid,
            "found": True,
            "state_error": state_error,
        }
    return {"platforms": platforms_state, "uuid": uuid, "found": True}
