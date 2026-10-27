"""The query a rule sends to a platform, as ``opentide query --rule`` runs it."""

from __future__ import annotations

from dataclasses import dataclass

from opentide.models.rule import DetectionRule


class RuleQueryError(ValueError):
    """The rule has no query this platform can run."""


@dataclass(frozen=True)
class RuleQuery:
    text: str
    language: str | None = None
    index: tuple[str, ...] = ()
    data_view: str | None = None
    #: Names one of several queries (a SentinelOne correlation sub-query).
    label: str | None = None
    #: Said with the result: what the rows are not (a threshold the query omits).
    note: str | None = None


def rule_queries(rule: DetectionRule, platform: str) -> list[RuleQuery]:
    """The queries a deploy of *rule* sends to *platform*, in the order it sends them.

    Raises :class:`RuleQueryError` when the rule has no block for *platform*,
    or the block holds nothing a search can run (a HarfangLab Sigma rule, an
    Elastic machine-learning job).
    """
    configs = rule.platform_configs()
    config = getattr(configs, platform, None)
    if config is None:
        raise RuleQueryError(f"rule {rule.name!r} has no {platform} configuration")
    match platform:
        case "sentinel" | "defender_for_endpoint" | "crowdstrike":
            return [RuleQuery(_required(config.query, rule, platform))]
        case "carbon_black_cloud":
            # Deploy joins the lines of a multiline Lucene query with spaces.
            text = " ".join(_required(config.query, rule, platform).split())
            return [RuleQuery(text)]
        case "splunk":
            from opentide.platforms.splunk.client import create_query

            _required(config.query, rule, platform)
            return [RuleQuery(create_query(rule))]
        case "sentinel_one":
            return _sentinel_one_queries(config, rule)
        case "elastic":
            return [_elastic_query(config, rule)]
        case "harfanglab":
            raise RuleQueryError(
                f"rule {rule.name!r} is a HarfangLab Sigma or YARA rule, which the agents "
                "evaluate: it holds no query to search telemetry with. Pass a telemetry "
                "query instead, such as 'processes process_name=cmd.exe'"
            )
    raise RuleQueryError(f"{platform} rules cannot be queried")


def _required(text: str | None, rule: DetectionRule, platform: str) -> str:
    if not text or not text.strip():
        raise RuleQueryError(f"rule {rule.name!r} has an empty {platform} query")
    return text.strip()


def _sentinel_one_queries(config: object, rule: DetectionRule) -> list[RuleQuery]:
    condition = getattr(config, "condition", None)
    kind = getattr(condition, "type", None)
    if kind == "Single Event" and condition is not None and condition.single_event:
        return [RuleQuery(_required(condition.single_event.query, rule, "sentinel_one"))]
    if kind == "Correlation" and condition is not None and condition.correlation:
        sub_queries = condition.correlation.sub_queries
        return [
            RuleQuery(
                _required(sub.query, rule, "sentinel_one"),
                label=f"sub-query {number}",
                note="one correlation sub-query: the correlation itself is not applied",
            )
            for number, sub in enumerate(sub_queries, start=1)
        ]
    raise RuleQueryError(f"rule {rule.name!r} has no SentinelOne query")


def _elastic_query(config: object, rule: DetectionRule) -> RuleQuery:
    kind = getattr(config, "type", "query")
    if kind == "machine_learning":
        raise RuleQueryError(
            f"rule {rule.name!r} is an Elastic machine_learning rule, which has no query"
        )
    text = _required(getattr(config, "query", None), rule, "elastic")
    index = tuple(getattr(config, "index", None) or ())
    data_view = getattr(config, "data_view_id", None)
    if kind in ("esql", "eql"):
        return RuleQuery(text, language=kind, index=index, data_view=data_view)
    language = getattr(config, "language", None) or "kuery"
    note = None
    if kind != "query":
        note = f"the {kind} rule's event query only: the {kind} logic is not applied"
    return RuleQuery(text, language=language, index=index, data_view=data_view, note=note)
