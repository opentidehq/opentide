"""``opentide query``: run a read-only query on platform tenants and report the rows.

Shared by the CLI command and the MCP ``run_query`` tool, which return the
same payload.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from opentide.cli.context import CliContext
from opentide.cli.ui.contract import (
    COMMAND_FAILED,
    USAGE_EXIT_CODE,
    USAGE_INVALID_VALUE,
    did_you_mean,
)
from opentide.query.models import DEFAULT_LIMIT, DEFAULT_TIMEOUT

if TYPE_CHECKING:
    from opentide.models.rule import DetectionRule
    from opentide.query.runner import QueryRunner
    from opentide.query.service import QueryRun


def query_platform(
    ctx: CliContext,
    platform: str,
    *,
    query: str | None = None,
    rule_uuid: str | None = None,
    rule_file: str | None = None,
    tenants: Sequence[str] = (),
    since: str | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = DEFAULT_LIMIT,
    language: str | None = None,
    index: Sequence[str] = (),
    timeout: float = DEFAULT_TIMEOUT,
    runner: QueryRunner | None = None,
) -> dict[str, Any]:
    """Run *query*, or the query of the rule *rule_uuid* or *rule_file* names, on *platform*.

    The payload lists every tenant's outcome under ``results``. A tenant
    that refuses the query or cannot be reached fails the call (exit 1); the
    other tenants still run. A call that cannot run at all exits 2.
    """
    from opentide.query.service import QueryUsageError, run_query

    ctx.apply_environment()
    sources = [
        name
        for name, given in (("QUERY", query), ("--rule", rule_uuid), ("--file", rule_file))
        if given
    ]
    if len(sources) != 1:
        message = (
            "give exactly one query: QUERY (or - for stdin), --query-file, --rule or --file"
            if not sources
            else f"{' and '.join(sources)} cannot be combined: give one query"
        )
        return _usage(platform, message, argument=sources[-1] if sources else "QUERY")
    rule: DetectionRule | None = None
    if rule_uuid or rule_file:
        loaded = _load_rule(rule_uuid, rule_file, repo=ctx.repo)
        if isinstance(loaded, dict):
            return {"platform": platform, **loaded}
        rule = loaded
    try:
        run = run_query(
            platform,
            query=query,
            rule=rule,
            tenants=tenants,
            since=since,
            start=start,
            end=end,
            limit=limit,
            language=language,
            index=index,
            timeout=timeout,
            runner=runner,
        )
    except QueryUsageError as exc:
        return _usage(
            platform,
            str(exc),
            argument=exc.argument,
            suggestion=did_you_mean(exc.value, exc.choices) if exc.value else None,
            choices=exc.choices,
        )
    return run_payload(run, query=query)


def run_payload(run: QueryRun, *, query: str | None = None) -> dict[str, Any]:
    """The JSON payload of *run*: one ``results`` entry per tenant and query."""
    results = [outcome.to_dict() for outcome in run.outcomes]
    failed = [outcome for outcome in run.outcomes if not outcome.ok]
    rows = run.row_count
    tenants = len(run.tenants)
    where = f"{tenants} {run.platform} tenant{'s' if tenants != 1 else ''}"
    payload: dict[str, Any] = {
        "platform": run.platform,
        "source": "rule" if run.rule is not None else "query",
        "window": run.window.to_dict(),
        "limit": run.limit,
        "tenants": run.tenants,
        "results": results,
        "row_count": rows,
        "_summary": {"tenants": tenants, "rows": rows, "failed": len(failed)},
    }
    if run.rule is not None:
        payload["rule"] = {
            "uuid": str(run.rule.metadata.uuid),
            "name": run.rule.name,
            "queries": [item.text for item in run.queries],
        }
    else:
        payload["query"] = query.strip() if query else run.queries[0].text
    if failed:
        first = failed[0]
        payload.update(
            {
                "status": "failed",
                "message": (
                    f"{len(failed)} of {len(run.outcomes)} queries failed on {where}: "
                    f"{first.tenant}: {first.error}"
                ),
                "_exit_code": 1,
                "_failure_code": COMMAND_FAILED,
            }
        )
        if first.detail:
            payload["detail"] = first.detail
        return payload
    truncated = any(o.result is not None and o.result.truncated for o in run.outcomes)
    payload["status"] = "completed"
    payload["message"] = f"{rows} row{'s' if rows != 1 else ''} from {where}" + (
        f" (limited to {run.limit} per tenant)" if truncated else ""
    )
    return payload


def _load_rule(
    rule_uuid: str | None, rule_file: str | None, *, repo: Path
) -> DetectionRule | dict[str, Any]:
    """The rule to query, or a refusal payload naming why it cannot be read.

    *rule_file* is read from the current directory, else from the repository root.
    """
    if rule_file:
        from opentide.core.io import load_yaml
        from opentide.loading.rule_loader import load_rule_from_dict

        path = Path(rule_file)
        if not path.is_file() and not path.is_absolute() and (repo / path).is_file():
            path = repo / path
        if not path.is_file():
            return _refusal(f"no rule file at {rule_file}", argument="--file")
        try:
            data = load_yaml(path)
            if not isinstance(data, dict):
                raise ValueError("the file does not hold one rule mapping")
            return load_rule_from_dict(data, file=path)
        except Exception as exc:  # A YAML or model error: the file is the user's to fix.
            return _refusal(f"cannot read the rule in {rule_file}: {exc}", argument="--file")
    from opentide.core.registry import Opentide

    assert rule_uuid is not None
    rules = Opentide.Rules
    # UUIDs compare case-insensitively (RFC 9562); one pasted from a console may be upper case.
    wanted = rule_uuid.strip().lower()
    match = next((key for key in rules if str(key).lower() == wanted), None)
    if match is None:
        suggestion = did_you_mean(rule_uuid, rules)
        return _refusal(f"no rule with UUID {rule_uuid}", argument="--rule", suggestion=suggestion)
    return rules[match]


def _refusal(message: str, *, argument: str, suggestion: str | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": "failed",
        "message": message,
        "_exit_code": USAGE_EXIT_CODE,
        "_failure_code": USAGE_INVALID_VALUE,
        "_failure_argument": argument,
    }
    if suggestion:
        payload["_failure_suggestion"] = suggestion
    return payload


def _usage(
    platform: str,
    message: str,
    *,
    argument: str,
    suggestion: str | None = None,
    choices: Sequence[str] = (),
) -> dict[str, Any]:
    payload = {"platform": platform, **_refusal(message, argument=argument, suggestion=suggestion)}
    if choices:
        payload["choices"] = list(choices)
    return payload
