---
title: opentide query
description: Run a read-only query on one, several or all tenants of a platform and get the rows back, from a query you type or from a rule.
---

# opentide query

Runs a read-only query on a platform's tenants and prints the rows. Use it to try a detection against real telemetry without leaving the terminal: the query you are writing, or the query a rule deploys.

```bash
opentide query --platform sentinel 'SecurityEvent | where EventID == 4688 | take 20'
opentide query --platform splunk --rule <rule-uuid> --tenant all --since 7d
opentide query --platform elastic --language eql --index 'logs-*' 'process where process.name == "cmd.exe"'
opentide --json query --platform defender_for_endpoint --file objects/rules/suspicious-lsass.yaml
```

`opentide validate query --live` checks that a query runs; `opentide query` returns what it finds.

## Arguments and options

| Input | Purpose |
|-------|---------|
| `[QUERY]` | The query, in the platform's language. `-` reads it from stdin |
| `--platform` | Required. `sentinel`, `defender_for_endpoint`, `splunk`, `sentinel_one`, `carbon_black_cloud`, `crowdstrike`, `harfanglab` or `elastic` |
| `--tenant` | A configured tenant name (repeatable), or `all`. Default: the only tenant configured |
| `--rule` | Run the query this rule (by UUID) deploys to the platform |
| `--file` | Run the query of the rule in this YAML file, saved or not: a path from the current directory or the repository root |
| `--query-file` | Read the query from this file |
| `--since` | Look back this far from `--to` or now: `15m`, `24h`, `7d`, `PT1H`. Default `24h` |
| `--from`, `--to` | An explicit window, ISO-8601. A time without an offset is UTC. `--since` and `--from` exclude each other |
| `--limit` | Rows per tenant, 1–10000. Default `100` |
| `--language` | Elastic only: `esql` (default), `eql`, `lucene` or `kuery` |
| `--index` | Elastic index pattern, or CrowdStrike repository (repeatable) |
| `--timeout` | Seconds to wait for an asynchronous search (SentinelOne, Carbon Black, CrowdStrike). Default `120` |
| `--columns` | Comma-separated columns the table shows |
| `--format` | `table` (default), `jsonl` or `csv`. `--json` prints the [envelope](./json-output.md) instead |

Give exactly one query: `QUERY`, `--query-file`, `--rule` or `--file`.

## Tenants

The query runs on the tenants `--tenant` names, in the order the platform file lists them. With no `--tenant`, a platform with one tenant uses it; with several, the command exits `2` and lists them, so a query never reaches a production tenant you did not name. `--tenant all` runs on every tenant. A rule's own `tenants` list and the tenants' `strategies` do not restrict a query.

Each tenant runs independently: one that refuses the query or cannot be reached is reported, and the others still return their rows.

## What runs on each platform

| Platform | API | Language | Window | Limit |
|----------|-----|----------|--------|-------|
| Sentinel | Log Analytics `query_workspace` | KQL | `timespan` | appends `\| take N+1` unless the query ends in `take`/`limit` |
| Defender | Graph `runHuntingQuery` | KQL | `Timespan` interval, at most 30 days | as Sentinel |
| Splunk | one-shot search job (no saved search) | SPL; a query not starting with `\|` gets `search` | `earliest_time`/`latest_time` | `count` |
| SentinelOne | PowerQuery `dv/events/pq`, polled with `pq-ping` | PowerQuery | `fromDate`/`toDate` | appends `\| limit N+1` |
| Carbon Black | process search | Lucene | `time_range` | `rows` |
| CrowdStrike | Next-Gen SIEM query job, stopped on timeout | CQL | `start`/`end` | appends `\| head(limit=N+1)` |
| HarfangLab | telemetry API | a source and `field=value` filters (below) | `@event_create_date` | `limit` |
| Elastic | ES\|QL `_query`, EQL `_eql/search`, Lucene `_search` | `--language` | `@timestamp` range filter | `LIMIT`, `size` |
| Elastic `kuery` | detection rule preview | KQL | the rule's look-back | the rule's `max_signals` |

One row past `--limit` is requested, so a result knows when more matched: `truncated` is `true` and the table says `more matched; raise --limit`.

**Elastic KQL.** Kibana runs KQL only inside detection rules, so a `kuery` query is previewed as a rule and the rows are the alerts the preview raised, with the alert bookkeeping (`kibana.*`) removed. Each result carries a warning saying so. ES|QL, EQL and Lucene return events directly. EQL and Lucene search `--index`, else the rule's `index` or data view, else the tenant's `setup.index`.

**HarfangLab.** The telemetry API filters one source by fields; it has no query language. A query names the source, then filters the API applies as given:

```text illustrative
processes process_name=powershell.exe agent.hostname=WS01
dns requested_name=example.org
network 'commandline__icontains=invoke-webrequest'
```

Sources: `processes`, `binary`, `network`, `eventlog`, `dns`, `windows_authentications`, `linux_authentications`, `macos_authentications`. A HarfangLab rule is a Sigma or YARA rule the agents evaluate, so `--rule` refuses it: pass a telemetry query instead.

**CrowdStrike.** The API client needs the `NGSIEM: Read` scope (deploy's correlation-rule scope is not enough). The repository is `search-all` unless `--index` names another, such as `investigate_view`.

**Defender.** The app registration needs `ThreatHunting.Read.All`.

## Rules

`--rule` and `--file` send the query `deploy` would send:

- Splunk: the query with the MDR mapping macro deploy appends.
- SentinelOne correlation rules: each sub-query, as its own result labelled `sub-query 1`, `sub-query 2`… The correlation itself is not applied, and each result says so.
- Carbon Black: the lines of a multiline query joined with spaces.
- Elastic: the rule's language (`esql`, `eql`, or `kuery`/`lucene` for the other types) and its index or data view. For `threshold`, `new_terms` and `threat_match` rules only the event query runs, and the result says so; `machine_learning` rules have no query.

`--language` and `--index` override the rule's own.

## Output

Without `--json`, each tenant prints its name, the row count and a table of up to eight columns; `--columns` picks others. Warnings (a partial result, a preview) go to stderr. The outcome line counts the rows:

```text illustrative
lab  2 rows
 host     count
 ──────────────
 ws-01    12
 ws-02    3

✓ 2 rows from 1 splunk tenant
```

`--format jsonl` writes one JSON object per row and `--format csv` one line per row, each with a `_tenant` column (and `_label` for a rule with several queries). Nested values are JSON. Only rows reach stdout; an error goes to stderr.

With `--json`, for a Splunk tenant (sample values):

```json illustrative
{
  "ok": true,
  "status": "completed",
  "message": "2 rows from 1 splunk tenant",
  "platform": "splunk",
  "source": "query",
  "query": "index=main | stats count by host",
  "window": {"from": "2026-10-26T08:00:00.000Z", "to": "2026-10-27T08:00:00.000Z"},
  "limit": 100,
  "tenants": ["lab"],
  "results": [
    {
      "tenant": "lab",
      "status": "ok",
      "columns": [{"name": "host", "type": null}, {"name": "count", "type": null}],
      "rows": [{"host": "ws-01", "count": "12"}, {"host": "ws-02", "count": "3"}],
      "row_count": 2,
      "truncated": false,
      "partial": false,
      "language": "spl",
      "sent": "search index=main | stats count by host",
      "warnings": [],
      "elapsed_ms": 812
    }
  ],
  "row_count": 2
}
```

A failed tenant has `status: "failed"`, `error` and, when the platform gave one, `detail` (the parser's message). `sent` appears when the query sent differs from the one given. `partial` is `true` when the platform stopped early (a Sentinel partial result, an Elastic time-out). For a rule, `rule` replaces `query`: `{uuid, name, queries}`.

## Exit codes

| Code | When |
|------|------|
| `0` | Every tenant answered, rows or none |
| `1` | A tenant refused the query or could not be reached; the others' rows are still printed |
| `2` | The call could not run: no query or two, an unknown rule, tenant or language, a bad window, no tenant configured |

## Safety

The command only reads. No saved search, rule or job outlives the call: Splunk runs a one-shot job, CrowdStrike's job is stopped when the command stops waiting, and Elastic's preview writes only to the preview index. Credentials come from the platform file, as for `deploy`; an unset `$VAR` refuses the tenant before anything is sent. Rows are telemetry: nothing is written to disk unless you redirect stdout.

## Related

- [`opentide validate query`](./validate.md) — check that rule queries run, in CI
- MCP [`run_query`](../mcp/tools.md#run_query) — the same query from an agent
- [`DetectionRule.run_query`](../sdk/models.md#delegation-methods) — the same from Python
