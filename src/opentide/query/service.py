"""Run a query on the selected tenants of a platform: the core of ``opentide query``.

The CLI, the MCP ``run_query`` tool and :meth:`DetectionRule.query` all call
:func:`run_query`; each renders the :class:`QueryRun` it returns.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass, field

import structlog

from opentide.core.errors import Errors
from opentide.models.rule import DetectionRule
from opentide.models.system_config import SystemConfig
from opentide.query.models import (
    DEFAULT_LIMIT,
    DEFAULT_TIMEOUT,
    MAX_LIMIT,
    QueryRefused,
    QueryRequest,
    TenantOutcome,
    TimeWindow,
)
from opentide.query.rules import RuleQuery, RuleQueryError, rule_queries
from opentide.query.runner import QUERY_PLATFORMS, QueryRunner, RunnerUnavailable, load_runner
from opentide.query.tenants import TenantSelectionError, select_tenants
from opentide.query.window import WindowError, resolve_window

logger = structlog.get_logger(__name__)

#: The languages each platform's runner takes; the first is the default.
PLATFORM_LANGUAGES: dict[str, tuple[str, ...]] = {
    "sentinel": ("kql",),
    "defender_for_endpoint": ("kql",),
    "splunk": ("spl",),
    "sentinel_one": ("powerquery",),
    "carbon_black_cloud": ("lucene",),
    "crowdstrike": ("cql",),
    "harfanglab": ("telemetry",),
    "elastic": ("esql", "eql", "lucene", "kuery"),
}

#: The address a transport failure is reported against, for tenants configured without a URL.
_DEFAULT_HOSTS = {
    "sentinel": "https://api.loganalytics.io",
    "defender_for_endpoint": "https://graph.microsoft.com",
    "crowdstrike": "https://api.crowdstrike.com",
}


class QueryUsageError(ValueError):
    """The call cannot run as given: ``argument`` names the flag at fault."""

    def __init__(
        self,
        message: str,
        *,
        argument: str,
        value: str | None = None,
        choices: Sequence[str] = (),
    ) -> None:
        super().__init__(message)
        self.argument = argument
        self.value = value
        self.choices = tuple(choices)


@dataclass
class QueryRun:
    """Every tenant's outcome for every query a call sent."""

    platform: str
    window: TimeWindow
    limit: int
    queries: list[RuleQuery]
    tenants: list[str]
    outcomes: list[TenantOutcome] = field(default_factory=list)
    rule: DetectionRule | None = None

    @property
    def ok(self) -> bool:
        return all(outcome.ok for outcome in self.outcomes)

    @property
    def row_count(self) -> int:
        return sum(len(o.result.rows) for o in self.outcomes if o.result is not None)


def run_query(
    platform: str,
    *,
    query: str | None = None,
    rule: DetectionRule | None = None,
    tenants: Sequence[str] = (),
    since: str | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = DEFAULT_LIMIT,
    language: str | None = None,
    index: Sequence[str] = (),
    timeout: float = DEFAULT_TIMEOUT,
    runner: QueryRunner | None = None,
) -> QueryRun:
    """Run *query*, or *rule*'s query for *platform*, on the tenants *tenants* names.

    Raises :class:`QueryUsageError` before contacting any tenant when the call
    cannot run. A tenant that refuses the query, or cannot be reached, is a
    failed :class:`TenantOutcome`; the other tenants still run.
    """
    if platform not in QUERY_PLATFORMS:
        raise QueryUsageError(
            f"{platform} has no query runner",
            argument="--platform",
            value=platform,
            choices=sorted(QUERY_PLATFORMS),
        )
    if (query is None) == (rule is None):
        raise QueryUsageError(
            "give exactly one query: QUERY, --query-file, --rule or --file", argument="QUERY"
        )
    if not 1 <= limit <= MAX_LIMIT:
        raise QueryUsageError(
            f"--limit must be between 1 and {MAX_LIMIT}", argument="--limit", value=str(limit)
        )
    if timeout <= 0:
        raise QueryUsageError("--timeout must be positive", argument="--timeout")
    languages = PLATFORM_LANGUAGES[platform]
    if language is not None and language not in languages:
        raise QueryUsageError(
            f"{platform} queries are {', '.join(languages)}, not {language!r}",
            argument="--language",
            value=language,
            choices=languages,
        )
    try:
        window = resolve_window(since, start, end)
    except WindowError as exc:
        raise QueryUsageError(str(exc), argument="--since") from None
    queries = _queries(platform, query, rule, language=language, index=index)
    try:
        selected = select_tenants(platform, tenants)
    except TenantSelectionError as exc:
        raise QueryUsageError(
            str(exc), argument="--tenant", value=exc.value, choices=exc.choices
        ) from None
    except ValueError as exc:  # A configuration file the loader refused.
        raise QueryUsageError(str(exc), argument="--platform", value=platform) from None
    run = QueryRun(
        platform=platform,
        window=window,
        limit=limit,
        queries=queries,
        tenants=[tenant.name for tenant in selected],
        rule=rule,
    )
    if runner is None:
        try:
            runner = load_runner(platform)
        except RunnerUnavailable as exc:
            run.outcomes = [
                TenantOutcome(tenant=tenant.name, error=str(exc)) for tenant in selected
            ]
            return run
    for tenant in selected:
        for item in queries:
            request = QueryRequest(
                platform=platform,
                text=item.text,
                window=window,
                limit=limit,
                language=item.language,
                index=item.index,
                data_view=item.data_view,
                label=item.label,
                timeout=timeout,
            )
            outcome = run_on_tenant(runner, request, tenant)
            if item.note:
                outcome.warnings.insert(0, item.note)
            run.outcomes.append(outcome)
    return run


def _queries(
    platform: str,
    query: str | None,
    rule: DetectionRule | None,
    *,
    language: str | None,
    index: Sequence[str],
) -> list[RuleQuery]:
    if rule is not None:
        try:
            found = rule_queries(rule, platform)
        except RuleQueryError as exc:
            raise QueryUsageError(str(exc), argument="--rule") from None
        if language is not None or index:
            # An explicit flag wins over the rule's own language or index.
            found = [
                RuleQuery(
                    item.text,
                    language=language or item.language,
                    index=tuple(index) or item.index,
                    data_view=None if index else item.data_view,
                    label=item.label,
                    note=item.note,
                )
                for item in found
            ]
        return found
    text = (query or "").strip()
    if not text:
        raise QueryUsageError("the query is empty", argument="QUERY")
    default = PLATFORM_LANGUAGES[platform][0]
    return [RuleQuery(text, language=language or default, index=tuple(index))]


def run_on_tenant(
    runner: QueryRunner, request: QueryRequest, tenant: SystemConfig.Tenant
) -> TenantOutcome:
    """*request* on *tenant*: its rows, or the reason it has none."""
    from opentide.platforms.transport import TenantUnreachableError, reaching_tenant

    outcome = TenantOutcome(tenant=tenant.name, label=request.label)
    began = time.monotonic()
    setup = getattr(tenant, "setup", None)
    host = str(getattr(setup, "url", "") or _DEFAULT_HOSTS.get(request.platform, ""))
    logger.info("query_sent", platform=request.platform, tenant=tenant.name, label=request.label)
    try:
        with reaching_tenant(request.platform, tenant.name, host):
            outcome.result = runner.run(request, tenant)
    except QueryRefused as exc:
        outcome.error = exc.message
        outcome.detail = exc.detail
    except TenantUnreachableError as exc:
        outcome.error = str(exc)
    except Errors.TenantConnectionError as exc:
        outcome.error = f"cannot authenticate to {request.platform} tenant {tenant.name!r}: {exc}"
    except ValueError as exc:
        # Unset ``$VAR`` credentials, an unparsable tenant setting.
        outcome.error = str(exc)
    except Exception as exc:
        # Reported as this tenant's failure, with its type; the other tenants still run.
        logger.debug("query_failed", exc_info=True)
        outcome.error = f"{type(exc).__name__}: {exc}"
    outcome.elapsed_ms = int((time.monotonic() - began) * 1000)
    return outcome
