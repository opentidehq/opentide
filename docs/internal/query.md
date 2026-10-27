---
title: opentide query (design)
description: How opentide query, MCP run_query and DetectionRule.run_query run a read-only query on platform tenants, and the decisions behind them.
---

# `opentide query` — design

> Status: **implemented** on every platform. Tracked by
> [#665](https://github.com/opentidehq/opentide/issues/665). The user-facing
> reference is [opentide query](../cli/query.md).

## Problem

Writing a detection means iterating on a query against real telemetry. Before
this command the loop left opentide: copy the query into the Sentinel,
Defender, Splunk or Kibana console, read the hits, paste the edit back.

`opentide validate query --live` already authenticated to every tenant, but it
answered one question — *does the query run?* — and threw the answer away.
Its validators are rule-centric (they take a deploy plan), signal failure only
through the `VALIDATION_ERROR_RAISED` process flags, and Splunk and Carbon
Black only parse. MCP `run_query` was an explicit stub.

## Decisions

| Question | Decision |
|----------|----------|
| Name | `opentide query`. MCP already has a catalogue `search` tool; the MCP tool stays `run_query`. |
| Tenants | `--tenant NAME` (repeatable) or `--tenant all`. No flag: the only tenant; with several, exit `2` and list them, so a production tenant is never queried unasked. A rule's `tenants` and the tenants' `strategies` do not restrict a query. |
| Platforms | All eight. CrowdStrike runs on Next-Gen SIEM; HarfangLab, which has no telemetry query language, takes a source and field filters and refuses `--rule`. |
| Failure | Per tenant: one tenant's refusal or outage is its outcome; the rest still run. Exit `1` if any failed, `2` if nothing could run. |
| Gate | The CLI command is the explicit act. MCP `run_query` refuses until `live: true`, like `validate_query`. |
| Row cap | `--limit` default 100 (`MAX_QUERY_ROWS`), at most 5 000; runners ask for one row more to report `truncated`, which stays under the 10 000-row caps of Elasticsearch and Carbon Black. |
| Window | Sent natively to each API, never spliced into the query text. |

## Layout

```
src/opentide/query/
  models.py    QueryRequest, QueryResult, QueryColumn, TenantOutcome, QueryRefused, flatten, json_safe
  window.py    --since / --from / --to → TimeWindow (UTC)
  tenants.py   --tenant → configured tenants (build_system_config)
  rules.py     rule → the queries deploy sends (RuleQuery)
  runner.py    QueryRunner ABC, QUERY_PLATFORMS, load_runner, kql_with_limit
  service.py   run_query → QueryRun; QueryUsageError
src/opentide/platforms/<pkg>/runner.py   one QueryRunner per platform, declare()
src/opentide/cli/services/query.py       QueryRun → CLI / MCP payload
src/opentide/cli/commands/query.py       the command and its table / jsonl / csv renderers
```

`load_runner(platform)` imports only that platform's `runner` module, so one
broken SDK cannot block another platform, and `opentide query --help` loads no
engine (`opentide.query` resolves its exports lazily).

A runner raises `QueryRefused` for a vendor refusal (with the parser's message
as `detail`), lets transport errors through for `reaching_tenant` to report as
an unreachable tenant, and raises `Errors.TenantConnectionError` for failed
authentication. `run_on_tenant` turns each into a failed `TenantOutcome`.
Nothing goes through environment flags.

## Per-platform notes

- **Sentinel** — `LogsQueryClient.query_workspace(timespan=(start, end))`. A
  `LogsQueryPartialResult` is `partial: true` with the error as a warning; a
  multi-table answer keeps the first table and warns.
- **Defender** — Graph `runHuntingQuery` with an ISO-8601 interval `Timespan`;
  windows over 30 days are refused before sending.
- **Splunk** — `jobs.oneshot(..., count=N+1, output_mode="json")`: no saved
  search. `--rule` sends `create_query(rule)`, the deploy query with its MDR
  mapping macro.
- **SentinelOne** — PowerQuery `POST dv/events/pq`, then `GET dv/events/pq-ping`
  with exponential back-off until `FINISHED`, bounded by `--timeout`.
- **Carbon Black** — `select(Process).where(q).set_time_range().set_rows(N+1)`
  with the SDK timeout.
- **CrowdStrike** — LogScale query job on `/humio/api/v1/repositories/{repo}/queryjobs`
  (`search-all` by default, `--index` for another), polled until `done`, and
  `DELETE`d when the command stops waiting.
- **HarfangLab** — `GET /api/data/telemetry/<Source>/` with the filters as
  given, `@event_create_date__gte/lte`, `ordering`, `limit`.
- **Elastic** — ES|QL `_query` with a `@timestamp` range `filter`; EQL
  `_eql/search` and Lucene `_search` (`query_string`) on `--index`, the rule's
  index or data view, or the tenant's `setup.index`. KQL has no public raw
  search API, so `kuery` previews a minimal query rule and reads
  `.preview.alerts-security.alerts-<space>`; the rows are alerts, and say so.

## Testing

- `tests/test_query/` — window, tenant selection, rule queries, KQL limit,
  service behaviour with a stand-in runner.
- `tests/test_platforms/test_query_runners.py` — every runner against
  stand-in vendor answers: request shape, column mapping, truncation, partial
  results, refusals, polling, time-outs and CrowdStrike's job stop.
- `tests/test_cli/test_query_cli.py` — the command on the corpus with two
  configured tenants: JSON envelope against its result model, tenant
  selection, per-tenant failure, rule and file sources, stdin, table, jsonl,
  csv and exit codes.
- `tests/test_mcp/test_tools_query.py` — the `live` gate and the hand-off to
  the CLI service.

Live tenants are not exercised in CI (no credentials there).

## Follow-ups

- Rebuild `validate query --live` on the runners (`limit 1`, short window) and
  retire the environment flags ([#673](https://github.com/opentidehq/opentide/issues/673)).
- A results pane in `opentide tui` ([#632](https://github.com/opentidehq/opentide/issues/632)).
- Sigma-to-filter translation for `opentide query --rule` on HarfangLab, if a
  safe subset proves useful.
