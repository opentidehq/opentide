---
title: opentide search (proposal)
description: Design for a read-only command that runs a query on a platform tenant and returns the rows, from the CLI, the SDK and MCP.
---

# `opentide search` — proposal

> Status: **proposed**. Tracked by [#665](https://github.com/opentidehq/opentide/issues/665);
> each section below names the slice that delivers it.

## Problem

Writing a detection means iterating on a query against real telemetry. Today
the loop leaves opentide: the author copies the query into the Sentinel,
Defender, Splunk or Kibana console, looks at the hits, and pastes the edit back
into the rule file.

`opentide validate query --live` already authenticates to every tenant, but it
answers one question — *does the query parse and run?* — and throws the answer
away:

| Platform | What `validate query --live` sends | Rows returned to the user |
|----------|------------------------------------|:-------------------------:|
| Sentinel | `LogsQueryClient.query_workspace(query + " \| limit 1", 1 min)` | none |
| Defender | Graph `runHuntingQuery` (`PT1H`), checks returned columns | none |
| Splunk | `service.parse(...)` — parse only, never runs | none |
| SentinelOne | PowerQuery `POST /dv/events/pq`, last minute | none |
| Carbon Black | `validate_process_query` — parse only | none |
| Elastic | ES\|QL `_query`, `_resolve/index`, `_field_caps`, rule preview | none |
| CrowdStrike, HarfangLab | — (`can_validate is False`) | — |

Validators are rule-centric (they take a deploy plan, not a query), report only
through the `VALIDATION_ERROR_RAISED` / `VALIDATION_WARNING_RAISED` process
flags, and log rows nowhere. The MCP server advertises `run_query`, but it is an
explicit stub (`stub: true`, `rows: null`).

## Goal

```text illustrative
$ opentide search --platform sentinel --tenant soc-prod --since 24h \
    'SecurityEvent | where EventID == 4688 | project TimeGenerated, Computer, CommandLine'
$ opentide search --platform splunk --rule 5e791284-… --since 7d --limit 50
$ opentide --json search --platform defender_for_endpoint --file rules/foo.yaml
```

One read-only primitive — *run this query on this tenant over this window and
give me at most N rows* — exposed on three surfaces that share it:

- **CLI**: `opentide search` (table for people, `--json` / `--format jsonl|csv` for pipes).
- **SDK**: `DetectionRule.search(platform, …)` and `opentide.search.run(...)`.
- **MCP**: `run_query` stops being a stub.

### Non-goals

- Writing to a tenant. `search` never creates a saved search, rule or job that
  outlives the call (Splunk `oneshot`, S1 PowerQuery and CBC searches are
  transient on the vendor side).
- Replacing `validate query`. Validation stays the CI gate; it may later be
  re-implemented on top of the search engines (slice H).
- A query-language translator. Each platform runs its own language.

## Command surface (slice B)

```
opentide search --platform PLATFORM [QUERY]
    [--rule UUID | --file PATH | --query-file PATH | -]   # exactly one query source
    [--tenant NAME]          # default: the only tenant, else refuse and list them
    [--since 24h | --from ISO --to ISO]   # default --since 24h
    [--limit N]              # default 100, hard cap per platform (see below)
    [--columns a,b,c]        # client-side projection for the table
    [--format table|jsonl|csv]   # --json is the global envelope
    [--language kuery|lucene|eql|esql]   # Elastic only, raw queries
```

Rules:

1. **Query source.** Positional `QUERY`, `-` (stdin), `--query-file`, `--rule`
   or `--file`. `--rule`/`--file` read the platform block of the rule, exactly
   the query `deploy` would send (Splunk: `create_query(rule)`; S1 correlation:
   one search per sub-query, reported separately; Elastic: the rule's
   `language` and index/data view).
2. **Tenant.** Explicit `--tenant`, or the single configured tenant. With
   several and no flag the command refuses with exit 2 and lists the names; it
   never fans out to every tenant silently (a prod tenant must be chosen).
   A rule's own `tenants` list is *not* a restriction for search.
3. **Time.** `--since` takes the same duration grammar the Elastic durations
   module already parses (`15m`, `24h`, `7d`); `--from/--to` take ISO-8601.
   The window is sent natively (Sentinel `timespan`, Defender `Timespan`,
   Splunk `earliest_time/latest_time`, S1 `fromDate/toDate`, ES range filter
   on `@timestamp`), never spliced into the query text.
4. **Limit.** Default 100 (`MAX_QUERY_ROWS`, already defined for MCP). Applied
   server-side wherever the API allows (Splunk `count`, ES `size`, CBC `rows`,
   KQL `| take N` appended only when the query has no terminal `take/limit`),
   then truncated client-side. The result says `truncated: true` when more rows
   existed.
5. **Read-only and gated.** Like `validate query`, it needs the platform SDK
   extras and credentials; no `--live` flag is needed because running *is* the
   command, but the human renderer prints the tenant name before rows so a prod
   query is never anonymous.
6. **Exit codes.** `0` rows or no rows; `1` query refused by the platform
   (syntax, permission, timeout); `2` usage (no query, unknown tenant,
   unsupported platform). An empty result is success.
7. **Output purity.** Rows go to stdout; logs to stderr; `--json` emits the
   standard `CommandResult` envelope (see [CLI experience](./cli-experience.md)).

## Result model (slice A)

```python
@dataclass(frozen=True)
class SearchRequest:
    platform: str
    tenant: str
    query: str
    start: datetime          # UTC
    end: datetime            # UTC
    limit: int
    language: str | None = None   # Elastic, S1 correlation sub-query label, …

@dataclass(frozen=True)
class SearchColumn:
    name: str
    type: str | None         # vendor type string, kept verbatim

@dataclass(frozen=True)
class SearchResult:
    request: SearchRequest
    columns: tuple[SearchColumn, ...]
    rows: tuple[dict[str, JsonValue], ...]
    truncated: bool
    elapsed_ms: int
    partial: bool = False     # Sentinel LogsQueryPartialResult, ES timed_out
    warnings: tuple[str, ...] = ()
    vendor_query_id: str | None = None   # S1 queryId, Splunk sid, CBC job id
```

`--json` payload: `{platform, tenant, query, window: {from, to}, columns,
rows, row_count, truncated, partial, warnings, elapsed_ms}`. Rows are
JSON-safe (datetimes → ISO strings, bytes → base64). The MCP `run_query` tool
returns the same dict.

## Engine tier (slice A)

A third engine tier next to `RuleDeployer` and `QueryValidator`:

```python
class QuerySearcher(SearchEngine, ABC):
    #: Languages this platform's search accepts; the first is the default.
    languages: ClassVar[tuple[str, ...]]

    @abstractmethod
    def search(self, request: SearchRequest, tenant: SystemConfig.Tenant) -> SearchResult:
        """Run *request* on *tenant*; raise SearchRefused for a vendor refusal."""
```

- Module per platform: `opentide/platforms/<pkg>/searcher.py` exposing
  `declare()`, loaded by `PlatformLoader.query_searchers(only=[platform])`
  so one broken SDK cannot block another platform.
- `QUERY_SEARCH_PLATFORMS` frozenset next to `QUERY_VALIDATION_PLATFORMS`;
  the registry gains `Platform.can_search`, and `opentide info` /
  `opentide://platforms` show it. Unsupported platforms return
  `supported: false` — never a fake empty result (same rule as validation).
- Errors are **raised and returned as data**, not signalled through
  `os.environ` flags: `SearchRefused(platform, tenant, message, vendor_detail)`.
  Transport failures reuse `reaching_tenant(...)` / `transport_error(...)`.
- Every HTTP call has a timeout (`transport.DEFAULT_TIMEOUT` session adapter)
  and honours the tenant `ssl` setting via `tenant_tls_verify`.
- Clients are reused: searchers call new read-only methods on the existing
  `*Service` / `*Client` classes, not new HTTP code paths.

## Per-platform implementation

| Platform | API | Language(s) | Window | Server-side limit | Slice |
|----------|-----|-------------|--------|-------------------|:-----:|
| Sentinel | `azure.monitor.query.LogsQueryClient.query_workspace` | KQL | `timespan=(start, end)` | `\| take N` appended | C |
| Defender | Graph `POST /security/runHuntingQuery` (`Query`, `Timespan`) | KQL | ISO-8601 interval `start/end` (≤30 d) | `\| take N` appended | C |
| Splunk | `service.jobs.oneshot(q, earliest_time, latest_time, count=N, output_mode="json")` | SPL | native | `count` | D |
| Elastic | ES\|QL `POST /_query`; EQL `POST /<idx>/_eql/search`; Lucene `POST /<idx>/_search` `query_string` | esql, eql, lucene | `@timestamp` range filter | `size` / `LIMIT` | D |
| Elastic (kuery) | Rule preview API → read `.preview.alerts-security.alerts-<space>` | kuery | preview `timeframeEnd` + interval | preview size | D (stretch) |
| SentinelOne | PowerQuery `POST /dv/events/pq` → poll `GET /dv/events/pq-ping?queryId=` | S1QL / PowerQuery | `fromDate/toDate` | `\| limit N` | E |
| Carbon Black | `cbc_sdk` `api.select(Process).where(q).set_time_range(start=, end=)` (async job) | CBC Lucene | `set_time_range` | `set_rows(N)` | E |
| CrowdStrike | NG-SIEM / LogScale query jobs (FalconPy `NGSIEM.start_search` / `get_search_status`) | CQL | `start`/`end` | `\| head(N)` | G |
| HarfangLab | Telemetry search `GET /api/data/telemetry/<source>/?...` | field filters | `@timestamp__gte/lte` | `limit` | G (research) |

Notes per platform:

- **Sentinel** returns `LogsQueryPartialResult` on timeouts/row caps: surface
  it as `partial: true` with the error text in `warnings`, not as a failure.
  Multi-table results (`union`, `fork`) → take the primary table, warn.
- **Defender** `runHuntingQuery` caps at 100 000 rows / 30 days; the response
  has `schema` (`Name`, `Type`) and `results` — map directly to columns/rows.
  Reuse `DefenderForEndpointService.run_hunting_query`, adding a `timespan`
  parameter that accepts an interval.
- **Splunk** prefix `search ` when the query does not start with `|`, as the
  validator does; respect the tenant `app` namespace; `oneshot` keeps no job
  history beyond the TTL.
- **Elastic** queries need an index: the rule's `index` / `data_view_id`, or
  `--index`. Kuery has no public raw-search API — use rule preview (returns
  matching alerts, not raw events) and say so in `warnings`.
- **SentinelOne** PowerQuery is asynchronous: poll with backoff until
  `FINISHED`, bounded by `--timeout` (default 60 s); cancel the query on
  timeout/Ctrl-C (`DELETE /dv/events/pq/{queryId}` / cancel endpoint).
- **Carbon Black** searches are async jobs; same bounded polling and
  cancellation.

## MCP (slice F)

`run_query(query, platform, tenant, since="24h", limit=100)` calls the same
service function. It contacts a tenant, so the tool description says "ask a
person first", like `validate_query live: true`. Unsupported platforms keep
`supported: false`. The `stub` key is removed (changelog: breaking for clients
that keyed on it). Docs: `docs/mcp/tools.md#run_query`, `docs/mcp/index.md`,
`docs/usage/workflows/agentic-setup.md`.

## Security and safety

- Read-only APIs only; reviewed per platform in the slice PR.
- Credentials never appear in output, logs or crash reports (crash handler
  redaction already covers tenant setup fields).
- Results can contain sensitive telemetry: no file is written unless
  `--output` names one; the CLI never caches rows.
- The query text is passed as data in API bodies, never interpolated into a
  URL or shell (CodeQL `py/` injection classes).
- `--limit` hard caps (10 000 rows) protect the terminal and the tenant quota.

## Testing

- **Unit**: each searcher against recorded/mocked vendor responses (no
  network): column mapping, truncation, partial results, refusal, transport
  error, async polling + cancellation, TLS verify flag passed through.
- **CLI E2E** (`tide_corpus`): `--rule` / `--file` / positional / stdin
  sources, tenant selection refusal, `--json` envelope purity, `--format
  csv|jsonl`, exit codes 0/1/2, unsupported platform.
- **MCP**: in-process `run_query` with a fake searcher; stdio stream stays clean.
- Live smoke tests stay manual (no tenant credentials in CI).

## Delivery slices

| Slice | Scope | Depends on |
|-------|-------|------------|
| [A](https://github.com/opentidehq/opentide/issues/666) | `SearchRequest/SearchResult`, `QuerySearcher` tier, loader, registry `can_search`, time-window parsing, service function | — |
| [B](https://github.com/opentidehq/opentide/issues/667) | `opentide search` CLI command, renderers (table/jsonl/csv/json), docs `docs/cli/search.md`, E2E tests | A |
| [C](https://github.com/opentidehq/opentide/issues/668) | Sentinel + Defender searchers | A |
| [D](https://github.com/opentidehq/opentide/issues/669) | Splunk + Elastic (esql, eql, lucene; kuery via preview as stretch) | A |
| [E](https://github.com/opentidehq/opentide/issues/670) | SentinelOne + Carbon Black (async polling, cancellation) | A |
| [F](https://github.com/opentidehq/opentide/issues/671) | MCP `run_query` backed by search; SDK `DetectionRule.search` | A, B |
| [G](https://github.com/opentidehq/opentide/issues/672) | CrowdStrike NG-SIEM and HarfangLab telemetry — research then implement | A |
| [H](https://github.com/opentidehq/opentide/issues/673) | Re-implement `validate query --live` on searchers (`limit 1`, short window), retire the env-var flags | C–E |

Slices C, D, E and G are independent and can land in parallel once A is merged.

## Open questions

1. **Name.** The MCP server already has a `search` tool that searches the
   *catalogue*. `opentide search` (tenant) next to MCP `search` (catalogue) may
   confuse agents. Alternatives: `opentide query run`, `opentide hunt`. This
   proposal keeps `opentide search` for the CLI and `run_query` for MCP.
2. **Multi-tenant fan-out.** Is `--tenant all` (one result block per tenant)
   wanted in v1, or only explicit single-tenant?
3. **TUI.** Should the `opentide tui` work (CLI N) get a results pane that
   reuses `SearchResult`?
