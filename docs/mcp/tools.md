---
title: MCP tools
description: Tool reference for the opentide MCP server — parameters, behaviour, and response shapes.
---

# MCP tools

Registered in `crates/opentide-cli/src/mcp/server.rs`. Implementations in `crates/opentide-cli/src/mcp/tools.rs`.

Each tool below lists its parameters, an example call, and an example response so an agent knows exactly what to expect. The tool descriptions an agent reads in `tools/list` say the same in a few lines each.

The server's `instructions`, sent with the `initialize` response, open with the tagline (*Spec-driven development for agentic detection engineering*) and give the agent its workflow: search, draft from a template, call `validation_report` until it is clean, then preview with `deploy_rule` and `dry_run: true`. People review and merge, and run real deployments.

Every tool and resource answers for the files as they are on disk at the call. The server reads the workspace once and keeps it between calls: each call re-reads only the files changed, added or deleted since the last one. A `deploy_rule` that is not a dry run reads the workspace afresh, and the next call reads it again.

### Next actions

`validate_rule`, `validation_report` and `validate_query` add a `next_actions` list: the calls worth making next.

```json
{
  "tool": "explain",
  "arguments": { "code": "vocab_unknown" },
  "command": "opentide explain vocab_unknown",
  "reason": "what vocab_unknown means and how to fix it"
}
```

`tool` and `arguments` are the MCP call. `command` is the same step as an `opentide` command line, for an agent with a shell (the CLI's own `next_actions` are `{command, reason}`). The list is empty when there is nothing to do. Every other key of these payloads is unchanged.

### Titles and annotations

`tools/list` gives every tool a `title` and MCP's behaviour `annotations`, which hosts use to decide which calls need a person's approval. Each hint is true of every argument, so a tool that can write or contact a tenant under one argument says so for all of them.

| Tool | Title | `readOnlyHint` | `destructiveHint` | `idempotentHint` | `openWorldHint` |
|------|-------|:-:|:-:|:-:|:-:|
| `search` | Search the catalogue | true | false | true | false |
| `get_chaining` | Threat, objective and rule lineage | true | false | true | false |
| `coverage` | ATT&CK coverage | true | false | true | false |
| `validate_rule` | Validate a rule | true | false | true | false |
| `validation_report` | Validation report | true | false | true | false |
| `explain` | Explain a diagnostic code | true | false | true | false |
| `validate_query` | Validate a query | true | false | true | true |
| `run_query` | Run a query on a tenant | false | false | false | true |
| `deploy_rule` | Deploy a rule | false | true | false | true |
| `deployment_status` | Deployment status | true | false | true | false |

`validate_query` reads only the workspace offline, but `live: true` contacts the tenant. `run_query` saves no search or rule, yet an Elastic `kuery` runs a rule preview that writes its alerts to the preview index, so it is not read-only. `deploy_rule` is marked for `dry_run: false`, which creates or replaces the rule on the tenant (a repeat can create it twice when no deployment state was recorded); with `dry_run: true`, the default, it only plans.

### Failures and `isError`

A tool that ran and could not do what it was asked answers with MCP's tool-level error: `isError: true`, and the same JSON an answer has, so a client that reads the payload sees what it always did (`status`, `message`, `error`). A tool that answers with what it found does not:

| Tool | `isError: true` when | Still an answer (`isError: false`) |
|------|----------------------|------------------------------------|
| `validate_query` | nothing was checked: the platform is unsupported, there is no offline engine (SentinelOne), an argument is refused (an unknown `stack`), or a live check could not run (no tenant configured, the tenant refused the credential or could not be reached; on the WASI build without [`OPENTIDE_FETCH`](../cli/mcp.md#tenant-requests-over-stdio-opentide_fetch), `network_unavailable`) | a verdict, whichever it is: the query is invalid (`valid: false`, with its diagnostics) or valid; and a live check every tenant answered, which adds `valid` to the command's document (`valid: false` when a tenant rejected a query, `status: "failed"`). The rejected queries are listed in `rejected`, each with the rule's `file` and `line`. A check that got no answer is not a rejection: a read timeout, a gateway's 502, 503 or 504, or a search still running at the deadline is listed in `timed_out`, the document has no `valid`, and the call failed |
| `run_query` | the call did not run (not `live`, an unknown tenant, no query, an unknown platform) or `status` is `failed`: every tenant failed, or some did (the rows of the others are in the payload) | `status: "completed"` |
| `deploy_rule` | `action` is `error`: the rule is missing, has no block for the platform, or could not be deployed (a tenant that refused the credential or could not be reached, a refused rule, `network_unavailable`) | a dry-run preview (including one that lists failing rules), a deploy that went through |
| `validation_report` | `queries` is not one of the three (`{"ok": false, "error": ...}`) | the report, whatever it finds |
| `validate_rule` | the rule is not in the catalogue (missing input, as `deploy_rule` has it: `valid: false`, `errors` naming the UUID, no `issues`) | the rule's findings, whatever they are |
| every other tool | the call is malformed: a missing or mistyped argument, an unknown tool, no workspace | a lookup that finds nothing (`get_chaining`, `deployment_status`: `found: false`) |

Before the release candidates changed it, a failed live check, query or deploy answered `isError: false` with `status: "failed"` in the payload, as the Python server did.

## search

Search the catalogue by keyword, UUID, or ATT&CK technique. Use it first when you do not know a UUID.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | string | required | Search term |
| `type` | string | `""` | Object type filter: `rule`, `threat`, `objective`. Any other value is refused (`isError`), naming the three |
| `platform` | string | `""` | Platform filter |
| `status` | string | `""` | Rule status filter: a rule matches when one of its platform blocks has this `status` |
| `technique` | string | `""` | ATT&CK technique ID |
| `actor` | string | `""` | Threat actor filter |

```json
// call
{ "query": "credential access", "type": "objective", "technique": "T1059" }

// returns: list of match dicts
[
  {
    "uuid": "00000000-0000-4000-8002-000000000001",
    "type": "objective",
    "title": "Credential Access Objective",
    "status": null
  }
]
```

A rule's `status` is its platform blocks' statuses, comma-separated (`"PRODUCTION, STAGING"`), the ones deploy reads; it is `null` for threats, objectives and a rule without a block. Through 0.20.1 it was the rule-level `status`, which no command reads.

The return type is always a list of `{uuid, type, title, status}` summaries — a
UUID query yields at most one summary, an unknown UUID yields `[]`. Filters
apply to a UUID query too: `search(<rule uuid>, type="threat")` returns `[]`. Read
`opentide://rules/{uuid}` (or the matching `threats`/`objectives` resource) for
a full body.

Filter semantics:

- `platform` matches a configuration **key** exactly, so `sentinel` never
  returns `sentinel_one` rules.
- `technique` unions every location content can use: top-level `techniques`,
  `tags.techniques`, `tags.attack`, and `threat.att&ck`. Matching is
  case-insensitive.
- `actor` reads `threat.actors` (and `tags.actors`). Namespaced identifiers match
  on either form, so `att&ck::G0006` and `G0006` both hit.

## get_chaining

Return the threat → objective → rule lineage for a UUID, plus threat-to-threat links from `threat.chaining`. Use it to see which objects belong together before editing.

| Parameter | Type | Description |
|-----------|------|-------------|
| `uuid` | string | Threat, objective, or rule UUID; a signal UUID (`objective.signals[].uuid`) names its objective |
| `depth` | integer, 0 or more | Optional, default `1`. The hops from the object to follow, in each direction: threat ↔ objective ↔ rule, and `threat.chaining` links. `0` is the object alone. Pass a larger depth for more of the lineage |

```json
// call — objective that lists a threat and is the detection_model of a rule
{ "uuid": "00000000-0000-4000-8002-000000000001" }

// returns
{
  "uuid": "00000000-0000-4000-8002-000000000001",
  "found": true,
  "type": "objective",
  "graph": {
    "threats": ["00000000-0000-4000-8001-000000000001"],
    "objectives": ["00000000-0000-4000-8002-000000000001"],
    "rules": ["00000000-0000-4000-8003-000000000001"]
  },
  "lineage": {
    "threats": ["00000000-0000-4000-8001-000000000001"],
    "objectives": ["00000000-0000-4000-8002-000000000001"],
    "rules": ["00000000-0000-4000-8003-000000000001"]
  },
  "chaining_index": {}
}
```

With the default `depth` of 1, `rules` lists the rules whose `detection_model` is this objective, and `threats` the threats it lists. A threat's other objectives, or a rule's sibling rules, are two hops away: ask for `depth: 2` or more. When the lineage goes on beyond the depth, the answer adds `"truncated": true` and a `hint` that says to call again with a larger depth; neither is present when the answer holds the whole lineage.

When this threat has `threat.chaining` entries, `graph` stays `{relation: [vector_uuid, …]}` (for example `{"preceeds": ["…"]}`). `lineage` is still present and lists the threats, objectives, and rules reached through `objective.threats`, `rule.detection_model`, and those threat-to-threat links. `chaining_index` maps each returned threat that has `threat.chaining` entries to its relation, `{relation: [vector_uuid, …]}`. Every other returned object's graph is `lineage`, which is not repeated per object, so `chaining_index` is `{}` when no returned threat chains. An empty `graph` means the object has no lineage. A missing UUID returns `{ "uuid": "…", "found": false, "graph": {} }`.

A rule whose `detection_model` is a signal UUID belongs to the lineage of the objective that defines the signal, and an objective's `graph` lists such rules. Asking for a signal UUID returns its objective (`uuid`, `type: "objective"`) and adds `resolved_from: {"type": "signal", "uuid": "…"}`.

The UUID is matched case-insensitively and trimmed; `uuid` in the response is the object's UUID as written in the repository.

`depth` counts hops over the references in either direction, so a lineage is walked up and down: depth 2 from a rule includes the other rules of its objective (rule → objective → rule), and depth 2 from an objective includes the objectives that cover the same threats. `lineage`, `graph` and `chaining_index` hold only the objects within `depth` hops of the object: each `chaining_index` entry lists only UUIDs that the response returns. `depth: 0` returns the object alone: `graph` is `{}`, `lineage` stays and holds only the object, and `chaining_index` has at most the object's own relation. A depth at least as long as the longest path returns the whole lineage, without `truncated`. Through 1.0.0-rc.5 an omitted `depth` returned the whole lineage, and `chaining_index` repeated it under each of its objects, which reached megabytes on a large catalogue. A negative or non-integer `depth` fails the call (`isError: true`, `argument depth must be 0 or more, not -1`) and returns nothing.

## coverage

ATT&CK coverage analysis with gap identification. Use it to answer "what do we detect for T1059?" or "where are our gaps?".

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `technique` | string | `""` | When set, return coverage for that technique only |
| `tactic` | string | `""` | Echoed as `tactic_filter` when no technique is set; **does not filter** the matrix today |

Coverage counts the same rules as `opentide info coverage --technique <id>`: a rule
covers the techniques in its own `techniques`, and those it inherits from the objective
its `detection_model` names (directly, or through one of the objective's signals), or,
when that objective lists none, from the objective's threats. `own_rules` and
`inherited_rules` keep the two apart; `rules` holds both. In the matrix, `own_matrix`
lists only the rules that name each technique themselves.

Matching is case-insensitive, and a parent technique covers its sub-techniques:
`T1059` returns rules tagged `T1059` **and** `T1059.001`, `T1059.003`, … . A
sub-technique query does not widen to its parent — `T1059.001` does not return
a rule tagged only `T1059`. `matched_techniques` lists the identifiers that
answered, so you can tell parent-level from sub-technique-level coverage.

```json
// call
{ "technique": "T1059" }

// returns
{
  "technique": "T1059",
  "covered": true,
  "matched_techniques": ["T1059", "T1059.001"],
  "rules": ["00000000-0000-4000-8003-000000000001", "00000000-0000-4000-8003-000000000002"],
  "own_rules": ["00000000-0000-4000-8003-000000000001"],
  "inherited_rules": ["00000000-0000-4000-8003-000000000002"]
}
```

Without `technique`:

```json
{
  "technique_count": 12,
  "matrix": { "T1059": ["…8003…01", "…8003…02"], "T1003": ["…8003…02"] },
  "own_matrix": { "T1059": ["…8003…01"] },
  "tactic_filter": null
}
```

## validate_rule

Validate a single rule against its schema and cross-object checks.

| Parameter | Type | Description |
|-----------|------|-------------|
| `uuid` | string | Rule UUID |

**Returns:**

```json
{
  "valid": true,
  "errors": [],
  "warnings": [],
  "issues": [],
  "next_actions": [
    {
      "tool": "deploy_rule",
      "arguments": { "uuid": "00000000-0000-4000-8003-000000000001", "platform": "sentinel", "dry_run": true },
      "command": "opentide --json deploy --dry-run --strategy PREVIEW --all --platform sentinel",
      "reason": "preview the sentinel deployment; nothing is sent"
    }
  ]
}
```

`errors` and `warnings` are strings. `issues` are the report's issues with the [diagnostic fields](#diagnostic-fields), as `validation_report` returns them. A rule that fails points `next_actions` at `explain` for its first error code (each issue's `explain` field names its own code), and then at `validate_rule` again; a valid rule points at a dry-run `deploy_rule` for each platform it has a configuration block for, unless its status there maps to `INERT`. The `command` passes the `--strategy` values that deploy the rule's status (`PREVIEW` for a `STAGING` rule, `RELEASE` for a `PRODUCTION` one) and `--all`: it previews every rule those strategies deploy, this one among them (`--uuid <uuid>` in place of `--all` previews this rule alone). An unknown UUID points at `search` with an empty query, which lists every rule with its title (the `command`, `opentide --json info rules`, lists UUIDs only).

## validation_report

Structured validation report for agents. Full registry by default; narrow with filters. Call it after every edit, until `ok` is `true`.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file` | string | `""` | Single file: a repo-relative or absolute path matches that file only; a bare file name matches every object file with that name (as [`validate --file`](../cli/validate.md#selecting-a-file)) |
| `uuid` | string | `""` | Single UUID |
| `object_type` | string | `""` | `rule`, `threat`, or `objective`. Any other value is refused (`isError`, `usage_invalid_choice`), as `validate --type` refuses it |
| `queries` | string | `"error"` | How a query the platform would reject is reported, as [`validate --queries`](../cli/validate.md#queries): `error` (an issue), `warn` (a warning: `ok` stays `true`) or `off` (queries are not checked). Another value is an invalid argument (`isError`): `ok: false` and an `error` naming the three |

Every rule query is checked offline with the analysis engine, as `opentide validate` checks it; its style (the engine's warnings and notes) is `opentide lint`'s. Returns the validation report (`ok`, `issues`, `warnings`, `stats`) plus `next_actions`; `stats.queries_checked` counts the queries. A rule with `tlp: clearr`:

```json
// call
{ "file": "objects/rules/sentinel-kql-rule.yaml" }

// returns (one issue shown)
{
  "ok": false,
  "issues": [
    {
      "code": "vocab_unknown",
      "severity": "error",
      "object_uuid": "00000000-0000-4000-8003-000000000001",
      "object_type": "rule",
      "file_path": "/work/detections/objects/rules/sentinel-kql-rule.yaml",
      "yaml_line": 7,
      "field_path": ["metadata", "tlp"],
      "message": "Value \"clearr\" is not a valid \"tlp::1.0\" vocabulary entry",
      "suggestion": "clear",
      "context": { "vocab": "tlp::1.0", "value": "clearr" },
      "path": "objects/rules/sentinel-kql-rule.yaml",
      "line": 8,
      "column": 8,
      "end_line": 8,
      "end_column": 14,
      "help": "did you mean \"clear\"?",
      "fix": {
        "safe": false,
        "edits": [
          { "line": 8, "column": 8, "end_line": 8, "end_column": 14, "replacement": "clear" }
        ]
      },
      "explain": "opentide explain vocab_unknown"
    }
  ],
  "warnings": [],
  "stats": { "objects_checked": 1 },
  "next_actions": [
    {
      "tool": "explain",
      "arguments": { "code": "vocab_unknown" },
      "command": "opentide explain vocab_unknown",
      "reason": "what vocab_unknown means and how to fix it"
    },
    {
      "tool": "validation_report",
      "arguments": { "file": "objects/rules/sentinel-kql-rule.yaml" },
      "command": "opentide --json validate --file objects/rules/sentinel-kql-rule.yaml",
      "reason": "validate again after applying the fix edits"
    }
  ]
}
```

A report with errors points at `explain` for the first error code, then at `validation_report` again. When any fix is `safe`, that last step's `command` is `opentide --json validate --fix` with the same `--file`, `--uuid` or `--type`, which writes the safe fixes and validates again in one run, and its `reason` is `apply the safe fixes, then validate again`; `validate_rule` does the same with `--uuid`. A clean report has `ok: true` and an empty `next_actions`.

### The implementation

`opentide mcp start` is the Rust server ([opentide mcp start](../cli/mcp.md#mcp-start)): every tool, schema, resource and answer is the one opentide 0.28.1's Python server gave, and every tool and resource runs in Rust. A few answers are worded by opentide rather than by the Python libraries the Python server used:

- An argument that is missing or of the wrong type is refused in opentide's words (`Error executing tool search: argument query is required`, `argument code must be a string, not a number`, `argument live must be a boolean (true or false), not "sometimes"`, `argument limit must be an integer, not "many"`), where the Python server quoted Pydantic's validation error.
- `opentide://index` holds the paths, configuration, vocabularies, generated schemas, templates, objects and files of the workspace; it leaves out the Python registry's internal schema sources (`metaschemas`, `definitions`, `subschemas`) and the Python package's data folders under `paths`. The editor schemas are at `opentide://schemas/{object_type}` once `opentide generate schemas` has written them.

The Python server, and the variable that chose it, are gone ([#841](https://github.com/opentidehq/opentide/issues/841)).

### Diagnostic fields

Each entry of `issues` and `warnings` (and of `validate_rule`'s `issues`) carries the same fields as [`opentide --json validate`](../cli/json-output.md). They are added; every existing key keeps its value.

| Field | Meaning |
|-------|---------|
| `path` | Workspace-relative, `/`-separated. `file_path` stays absolute. |
| `line` | 1-based. `yaml_line` stays 0-based. |
| `object_uuid` | Already on every issue: the object at fault, or `""` |
| `column`, `end_column` | 1-based Unicode code points, best effort; `end_column` is one past the last character, on `end_line`. `null` when unknown. |
| `end_line` | 1-based line of the last character: equal to `line` for a span on one line, later for a query finding over several lines. `null` when `line` is. |
| `help` | A suggestion in prose (`did you mean "clear"?`), or `null` |
| `fix` | `{safe, edits: [{line, column, end_line, end_column, replacement}]}` or `null`. Each edit replaces the text from (`line`, `column`) up to (`end_line`, `end_column`). `safe` is `true` only when the value and the replacement spell the same word (they differ in case, spaces, `-` or `_`) and neither has a digit: apply those as they are. Check any other edit against `help` first; `clearr` → `clear` is not safe, and an ATT&CK id or an `invalid_ref` fix never is. See [`validate`](../cli/validate.md). |
| `explain` | `opentide explain <code>`; the `explain` tool returns the same page |

## explain

What a diagnostic code means, an example, and how to fix it: the page `opentide explain <code>` prints. Codes are listed in [Diagnostic codes](../cli/diagnostics.md).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `code` | string | `""` | An issue's `code`. Empty lists every code |

```json
// call
{ "code": "vocab_unknown" }

// returns
{
  "found": true,
  "code": "vocab_unknown",
  "meaning": "A value is not in the vocabulary its field uses.",
  "markdown": "# vocab_unknown\n\n…"
}
```

An unknown code returns `{"found": false, "code", "message", "suggestion"}`, with the closest code as `suggestion` (or `null`). An empty `code` returns `{"found": true, "codes": [{"code", "meaning"}, …]}`.

One cause is one issue, here and in `validate_rule`: a dangling reference (`detection_model`, `objective.threats`, `threat.chaining[].vector`) is an `invalid_ref`, not also a `vocab_unknown`, with the value in `context.value`. `opentide explain <code>` says what each code means.

## validate_query

Checks a query offline with the analysis engine, the same engine as `opentide validate query` and `opentide lsp`; with `live: true`, the catalogue's rules on the platform's tenants, the same path as `opentide validate query --platform <platform> --live`.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | string | | The query to check offline. The live check reads catalogue rules, not this string |
| `platform` | string | | Platform key: picks the language and the product's checks (Defender tables for `microsoft_defender`, the Carbon Black dialect for `carbon_black_cloud`, Graylog's Lucene for `graylog`, CQL for `crowdstrike`, Falco for `sysdig`, YARA under the HarfangLab or Bitdefender profile for `harfanglab` and `bitdefender`, the Exabeam Query Language for `exabeam`, YARA-L for `google_secops`). The query is checked as `position` says it will sit |
| `live` | boolean | `false` | `true` calls the tenant |
| `language` | string | `""` | Empty: the platform's language. Elastic, the one platform with several: `esql`, `eql`, `kuery` (the default) or `lucene` |
| `position` | string | `"search"` | Where the query will sit. `search`: as a query file of its language, so a CrowdStrike query is plain LogScale, an Exabeam query a search, and a YARA-L text a rule when it declares one. `rule`: as the platform's rule block checks its query, so a CrowdStrike query is a Next-Gen SIEM correlation rule (`cql_correlate_aggregate`), an Exabeam query a sequence filter (`exabeam_advanced_in_rule`) and a Datadog query a detection rule's; other languages check a rule's query as a search. Pass `rule` while drafting a rule's query. Any other value is refused with `status: "failed"` and `valid: null`. The result's `position` echoes it |
| `stack` | string | `""` | Elastic ES\|QL only: the stack the query must run on, `MAJOR.MINOR` such as `9.5`, or `serverless`. Empty: every supported stack. Any other value is refused with `status: "failed"` and `valid: null`, as an unknown `language` is |

Offline, the result has `valid` (`false` when the engine found an error), `status`, `language`, `errors`, `warnings`, every finding under `diagnostics` (`code`, `severity`, `message`, `line`, `column`, `end_line`, `end_column` in the query, 1-based, columns in code points; `suggestion`, the language's `reference` and `explain`), and `engine`, the version of the engine that checked it. Warnings (slow query shapes) leave `valid` true. The offline check knows the tables, indexes and index patterns the workspace's [`visibility.toml`](../usage/configuration.md#the-datasets-a-log-source-fills) declares, read afresh on each call as `opentide validate` and `lint` read it, so a declared table is known and, once a platform declares one, an undeclared one is a warning (`kql_table_not_declared`). A server with no workspace declares nothing. `next_actions` names the first finding's `explain` page, then the live check, for a platform that has one (CrowdStrike's CQL and Sysdig's Falco are checked offline only, so `live: true` returns `supported: false` for them).

```json
{
  "supported": true,
  "mode": "offline",
  "platform": "sentinel",
  "language": "kql",
  "valid": false,
  "status": "failed",
  "message": "1 error(s) in the kql query",
  "errors": [
    {
      "code": "kql_unknown_operator",
      "severity": "error",
      "message": "unknown tabular operator 'wher'",
      "line": 1,
      "column": 17,
      "end_line": 1,
      "end_column": 37,
      "suggestion": "where",
      "reference": "https://learn.microsoft.com/kusto/query/",
      "explain": "opentide explain kql_unknown_operator"
    }
  ],
  "warnings": [],
  "diagnostics": [
    {
      "code": "kql_unknown_operator",
      "severity": "error",
      "message": "unknown tabular operator 'wher'",
      "line": 1,
      "column": 17,
      "end_line": 1,
      "end_column": 37,
      "suggestion": "where",
      "reference": "https://learn.microsoft.com/kusto/query/",
      "explain": "opentide explain kql_unknown_operator"
    }
  ],
  "engine": {
    "engine": "1.0.0"
  },
  "next_actions": [
    {
      "tool": "explain",
      "arguments": {
        "code": "kql_unknown_operator"
      },
      "command": "opentide explain kql_unknown_operator",
      "reason": "how to fix it"
    },
    {
      "tool": "validate_query",
      "arguments": {
        "query": "SecurityEvent | wher EventID == 4688",
        "platform": "sentinel",
        "live": true
      },
      "command": "opentide --json validate query --platform sentinel --live",
      "reason": "check the catalogue's sentinel rules: this contacts the sentinel tenant with the configured credentials, so ask a person first"
    }
  ]
}
```

SentinelOne's S1QL has no offline engine: the default refuses and names `live: true`, and an empty `query` is refused too. Neither scans anything (`valid: null`). With `live: true` the result is the `opentide --json validate query --live` document without its envelope: `status` says whether the check failed, and `valid` (added by this tool) says whether the queries passed when every tenant answered every check; a tenant that could not be reached, refused the credential or gave no answer within the check timeout leaves `valid` out and fails the call (`isError`, [above](#failures-and-iserror)). A missing plan or a tenant it cannot reach is a failed live check.

**Unsupported platforms** return:

```json
{
  "valid": null,
  "supported": false,
  "mode": "unsupported",
  "message": "query validation not supported for …",
  "errors": []
}
```

Supported on the tenant: `carbon_black_cloud`, `microsoft_defender`, `elastic`, `datadog`, `exabeam`, `google_secops`, `graylog`, `sentinel`, `sentinel_one`, `splunk` (the registry's `live_check`; the tool description lists the same set). Offline: every platform but `sentinel_one`, the registry's `offline_languages`. The live next action says that it contacts the tenant with the configured credentials: ask a person before following it.

## run_query

Run a read-only query on a platform's tenants and return the rows: the MCP face of the [query command](../cli/query.md). Without `live: true` it refuses and contacts nothing; its next action is the live call. `live: true` uses the configured credentials: ask a person first.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | string | required | Query text in the platform's language (empty with `rule`) |
| `platform` | string | required | Platform key; every platform has a runner |
| `tenant` | string | `""` | A tenant name, several comma-separated, or `all`; empty for the only tenant |
| `live` | boolean | `false` | Send the query; without it nothing is sent |
| `rule` | string | `""` | Run the query this rule (UUID) deploys, instead of `query` |
| `since` | string | `"24h"` | Look-back: `15m`, `24h`, `7d`, `PT1H` |
| `limit` | integer | `100` | Rows per tenant (`MAX_QUERY_ROWS`), at most 5000 |
| `language` | string | `""` | Elastic only: `esql`, `eql`, `lucene` or `kuery` |
| `index` | string | `""` | Elastic index patterns (comma-separated), or a CrowdStrike repository |

Without `live`:

```json
{
  "supported": true,
  "status": "failed",
  "platform": "sentinel",
  "message": "run_query sends the query to the tenant. Pass live: true.",
  "query_preview": "SecurityEvent | take 10",
  "next_actions": [
    {
      "tool": "run_query",
      "arguments": {"query": "SecurityEvent | take 10", "platform": "sentinel", "live": true},
      "command": "opentide --json query --platform sentinel 'SecurityEvent | take 10'",
      "reason": "run it on sentinel: this contacts the tenant with the configured credentials, so ask a person first"
    }
  ]
}
```

With `live: true` the result is the query command's `--json` payload without its envelope, plus `supported: true`: `status` (`completed` or `failed`), `message`, `window`, `tenants`, `row_count`, and `results`, one per tenant (and per sub-query of a SentinelOne correlation rule) with `tenant`, `status` (`ok` or `failed`), `columns`, `rows`, `row_count`, `truncated`, `partial`, `warnings`, and on a failure `error` and `detail`. A call that cannot run (an unknown tenant, no query) has `status: "failed"` and a `message` naming the problem, and sends nothing. An unknown platform returns `supported: false`.

## deploy_rule

Deploy a rule to a platform. Defaults to a dry run — a real deploy requires an explicit `dry_run=false` and platform credentials.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `uuid` | string | required | Rule UUID |
| `platform` | string | optional | Platform key. Left out, it is the rule's only platform block; a rule with several answers an error (`action: "error"`) listing them in `platforms` |
| `dry_run` | boolean | `true` | Simulate when true |

```json
// call
{ "uuid": "00000000-0000-4000-8003-000000000001", "platform": "sentinel", "dry_run": true }

// returns
{
  "action": "dry-run",
  "tenant": null,
  "rule_id": "00000000-0000-4000-8003-000000000001",
  "status": "STAGING",
  "dry_run": true,
  "platform": "sentinel",
  "message": "Plan: 0 to create, 0 to update, 1 to create or update, 0 to disable, 0 to delete",
  "plan": { "sentinel": ["00000000-0000-4000-8003-000000000001"] },
  "changes": [{ "platform": "sentinel", "tenant": null, "uuid": "00000000-0000-4000-8003-000000000001", "name": "Sentinel KQL Rule", "status": "STAGING", "action": "upsert" }],
  "payloads": { "sentinel": [{ "uuid": "00000000-0000-4000-8003-000000000001", "api_request": { "kind": "Scheduled", "properties": {} } }] }
}
```

A dry run is the command line's `opentide --json deploy --dry-run --uuid <uuid> --platform <platform>`, run with the strategies the rule's status maps to. The answer is the fields above, `would_deploy` (whether anything would be sent), then the command's document: `plan`, `changes`, `payloads`, `diagnostics`, `warnings`, `missing_tenants` and the rest. `status` is the rule's block status; the command's own is `deploy_status`, and `message` is the command's. A rule that would fail still gets its preview, as an answer (`isError: false`): its `changes` row has `fails: true` and `diagnostics` says why. When nothing would deploy, `message` says why (`Nothing would deploy: sentinel is not enabled in this workspace; enable it with ...`, or the status maps to `INERT`), `would_deploy` is `false`, and `plan`, `changes` and `payloads` are empty. A dry run whose command printed no plan is an error (`action: "error"`, `error: "dry_run_failed"`).

`action` is `"dry-run"` or `"deploy"` (or `"error"` when the rule is missing, or has no block for `platform`). `status` is the `status` of the rule's block for `platform` (the status deploy reads), not a planned-action label. A rule with no block for `platform` (or a block with no `status`) is refused the same way with or without `dry_run`: `"action": "error"`, `"status": "error"` and a `message` such as `Rule "Sentinel KQL Rule" has no splunk status to deploy`, so the preview says what the real call would. So is a status the deployment configuration does not define: both answer `isError`, naming the statuses it defines. Through 0.20.1 it was the rule-level `status`, which no command reads and which defaulted to `STAGING` when left out.

A real deploy the deployer refused or failed returns `"action": "error"`, `"status": "failed"` and `"error": "deployment_failed"`, with no vendor call for a refused rule: for example a rule that still carries `rule_id` (`external_id_in_rule`), or a create whose id could not be written (`deployment_state_write_failed`). `message` is the cause, as the `error` of `opentide --json deploy` gives it: the platform, the rule and the tenant's or the platform's own words. Each call starts from a clean outcome, so one failed call does not mark the next as failed.

```json
{
  "action": "error",
  "tenant": null,
  "rule_id": "00000000-0000-4000-8003-000000000001",
  "status": "failed",
  "dry_run": false,
  "platform": "sentinel",
  "message": "Deployment to sentinel failed on Sentinel KQL Rule: sentinel tenant 'lab' setup: azure_client_secret names the environment variable AZURE_CLIENT_SECRET, which is unset",
  "error": "deployment_failed"
}
```

## deployment_status

Per-platform deployment state for a rule. Vendor rule ids come from the rule's [deployment state](../usage/concepts/deployment-state.md) shard, keyed by tenant.

| Parameter | Type | Description |
|-----------|------|-------------|
| `uuid` | string | Rule UUID |

```json
// call
{ "uuid": "00000000-0000-4000-8003-000000000001" }

// returns
{
  "found": true,
  "uuid": "00000000-0000-4000-8003-000000000001",
  "platforms": {
    "sentinel_one": {
      "deployed": true,
      "rule_id": "12345",
      "external_ids": { "contoso": "12345" },
      "tenants": []
    },
    "sentinel": {
      "deployed": true,
      "rule_id": null,
      "external_ids": {},
      "tenants": ["contoso"],
      "note": "opentide records no deployment state for sentinel: it addresses its rules without a vendor id, so a deploy leaves nothing here and deployed only says the rule's block names tenants. Ask the tenant: validate_query or run_query with live true; deploy_rule with dry_run true previews what a deploy sends."
    }
  }
}
```

`deployed` is true once a vendor id is recorded or the block names `tenants`. `external_ids` maps tenant name to the stored id (for the platforms that store one, below). `rule_id` is that id when exactly one tenant is bound, otherwise `null`. A shard that cannot be read adds `state_error` with its `deployment_state_*` code. A platform that addresses its rules without a vendor id (Sentinel, Microsoft Defender, Splunk, HarfangLab, Carbon Black Cloud and Elastic; the others store the id their vendor gives: SentinelOne, CrowdStrike, Sysdig, Bitdefender, Graylog, Exabeam, Google SecOps and Datadog) keeps no deployment state, so a deploy to it leaves nothing for this tool to read: it adds a `note` saying so, and `deployed` is true only when the rule's block names `tenants`, never because a deploy went through. Ask the tenant instead (`validate_query` or `run_query` with `live: true`).

## Agent workflows

Chain the tools into safe, end-to-end recipes.

### Add a detection for a technique

```text
search(query="T1059")                     → find or confirm the objective
get_chaining(uuid=<objective>)            → its threats and rules (depth 1); truncated → call again with a larger depth
# write objects/rules/<name>.yaml from opentide://templates/rule, detection_model=<objective>
validation_report(file=<new rule file>)   → apply each issue's fix.edits, explain(code) the rest
validation_report(file=<new rule file>)   → repeat until ok is true
# (tenant check: validate_query with live true, or opentide validate query --platform sentinel --live)
deploy_rule(uuid=<new rule>, platform="sentinel", dry_run=true)   → preview
# a person reviews, merges and deploys
```

### Audit coverage

```text
coverage()                                → technique_count + matrix of technique → rule UUIDs (own and inherited)
coverage(technique="T1059")               → covered bool + rules list for one technique
search(technique=<gap>)                   → confirm nothing exists
# propose new objective/rule for the gap
# note: tactic= is echoed only; it does not filter the matrix today
```

### Fix a broken reference

```text
validation_report(object_type="rule")     → surface dangling detection_model (invalid_ref)
get_chaining(uuid=<rule>)                 → inspect the related objects in lineage
# correct the UUID, then re-run validation_report
```

## Agent guidelines

1. Call `validation_report` before suggesting YAML edits, and again after each edit until `ok` is `true`.
2. Apply `fix.edits` from the issue rather than guessing; `safe: true` edits need no review, the others need a look at `help`. Call `explain` for a code you do not know.
3. Use `search` before `get_chaining` when the UUID is unknown.
4. Default to `dry_run=true` for `deploy_rule`; require explicit human approval for a real deploy. People review and merge changes.
5. Never claim query validation for unsupported platforms. `validate_query` checks the query offline; with `live: true` it checks the catalogue's rules against the tenant instead, so ask a person first. Ask a person before `run_query` with `live: true`, which queries a tenant with real credentials.
6. Do not assume `coverage(tactic=…)` filters results — pass `technique` for a filtered answer.

## Troubleshooting

- **Empty results everywhere** — the server likely started with the wrong `OPENTIDE_REPO_ROOT`, or schemas were never generated. See [Configuration](./configuration.md) and run `opentide generate` in the repo.
- **`validate_query` refuses** — SentinelOne's S1QL has no offline engine: pass `live: true` to check the catalogue rules against the tenant. On the other platforms the default checks the query offline. A missing plan or an unreachable tenant fails the live check.
- **A resource returns `{"error": "… not found"}`** — the UUID is wrong or the object type does not match; confirm with `search`.
- **`deploy_rule` crashes, or `deployment_status` says an undeployed rule is deployed** — through 0.6.3 an unknown platform raised `KeyError`, and any authoring config counted as deployed. 0.6.4 returns a structured failure for an unknown platform or a platform with no tenants. `deployed` is false when the config has no `external_id` and no tenants.
