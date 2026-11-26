---
title: "RFC: Datadog Cloud SIEM platform (draft)"
description: "Research and proposal for a fourteenth platform, datadog: Datadog Cloud SIEM detection rules as a Tide block, the Datadog search syntax as an engine language, deploy and live validation through the v2 Security Monitoring API, and the open-source content to start from."
---

# RFC: Datadog Cloud SIEM platform

> **Status: draft, for review.** Research done on 2026-11-26 against Datadog's online documentation,
> its public OpenAPI v2 specification and its open-source code. RFCs normally live in
> opentidehq/specifications `rfcs/`; this draft sits here until it is given a number there. The
> normative documents it calls for are a platform spec `specs/platforms/datadog-1.0.md` and a
> language spec `specs/languages/datadog-1.0.md` (sections 4 and 5 are their first drafts).
> Facts that the public sources did not settle are marked **(unverified)** and are listed in
> [Open questions](#11-open-questions). A companion explainer page, published separately, shows the
> YAML shape, the highlighting and a working prototype of the lexer and checks of sections 4.5 and
> 5.3 to 5.5; section 9.1 has what that prototype found in real queries.

## 1. Summary

Add **`datadog`, Datadog Cloud SIEM**, as the fourteenth built-in platform:

- **The block.** A `configurations.datadog` block (`platform::datadog::1.0`) describes one Cloud SIEM
  detection rule: real-time `log_detection` rules with the threshold, new value, anomaly and
  impossible travel methods; `signal_correlation` rules that can name other Tide rules; and, later,
  sequence and scheduled rules.
- **The language.** The Datadog search syntax (the "log search syntax" that Datadog's API calls
  `event_query`) becomes an engine language, id `datadog`, in a new pure-Rust crate
  `opentide-datadog`. It has a lossless tree, the existing HighlightSpec captures, catalogs and
  diagnostics. The case-condition expressions (`failed > 10 && success > 0`) get a small parser in
  the platform model, as Graylog's conditions do.
- **The connector.** Deploy (create, update, disable, delete) goes through
  `/api/v2/security_monitoring/rules`. `validate query --live` uses the vendor's own
  `POST /rules/validation`. `opentide query` uses the Logs Search API.
- **The starting content.** There is no open corpus of Datadog-format rules. The conformance corpus
  comes from the real queries in Datadog's integration assets (BSD-3-Clause). Seed rules come from
  Sigma's cloud rules (DRL 1.1), converted by our own mapping, and from 11 BSD-3 rules already in
  Datadog's format. The built-in rules recorded in the Terraform provider's tests are measured,
  never vendored. Section 9 lists every source and its licence; section 9.1 has what a prototype
  checker found in them.

Capability row as proposed (for the registry in `crates/opentide-schema/src/platforms.rs`):

| `--platform` | Product | Deploy | Compiled without a tenant | Tenant check (`--live`) | Offline engine | `opentide query` |
|---|---|:-:|:-:|:-:|---|---|
| `datadog` | Datadog Cloud SIEM | ✅ | ✅ | ✅ (`POST /rules/validation`) | Datadog search syntax (`.datadog`) | Datadog search syntax (Logs Search API) |

## 2. Motivation

Datadog Cloud SIEM is a common SIEM for cloud-native teams that already send their logs to
Datadog. Its detection rules are JSON documents behind a REST API. Datadog itself recommends
managing them as code, through Terraform (`datadog_security_monitoring_rule`) and the
validate, test, backtest and convert endpoints described in its "Detection as code for Cloud SIEM"
post (2025-06-11). There is no portable, vendor-neutral way to write those rules beside the
same detection for Sentinel, Splunk or Elastic. opentide exists to provide that.

The language is not well served today:

- **No grammar.** Datadog publishes no grammar, parser or TextMate grammar for the search syntax.
  Its VS Code extension has no `syntaxes/` folder. The closest thing to a reference
  implementation is the pest grammar in Datadog-owned [`vectordotdev/vrl`](https://github.com/vectordotdev/vrl)
  (`src/datadog/search/grammar.pest`, MPL-2.0), and it lacks `CIDR()`, `**`, escaped-space runs
  and calculated fields.
- **Silent traps in hand-written rules.** Several mistakes change what a rule matches without any
  error: a lower-case `and` becomes a search term, curly quotes are ignored, `*` inside quotes is
  punctuation, and an unescaped `:` in a value is misread. These are exactly the class of
  mistake opentide's offline checks exist to catch.

## 3. Scope

| In scope for `datadog-1.0` | Later (`datadog-1.x`) | Out of scope |
|---|---|---|
| `type: log_detection`, real time | `sequence_detection` (steps and transitions) | `workload_security` / `workload_activity`: Agent rules in SECL, a different language, the Datadog Agent's runtime policies |
| Detection methods `threshold`, `new_value`, `anomaly_detection`, `impossible_travel` | Scheduled rules (`schedulingOptions`, an RFC 5545 RRULE), `calculatedFields` (a formula language) | `application_security`, `api_security` (App and API Protection, ASM actions) |
| `type: signal_correlation`, referencing Tide rules or Datadog rule ids | `third_party` (`thirdPartyCases`, `rootQueries`) | `cloud_configuration`, `infrastructure_configuration` (CSPM, Rego) |
| `dataSource` `logs` (default), `audit`, `events`, `security_signals` | Reference tables (`referenceTables`) | `queryLanguage: sql` (DDSQL): SQL stays unsupported in opentide; a block that asks for it is refused with `datadog_sql_unsupported` |
| Live validation, deploy, disable, delete, drift by `version` | Tuning a Datadog default rule (`customQueryExtension`, `customStatus`, notifications), like Sysdig's `append_to_rule` | `hardcoded` (one value, `log4shell`, Datadog-owned) |
| `opentide query` over the Logs Search API | Rule tests through `POST /rules/test`; backtests through historical jobs (preview) | Suppression rules and security filters as their own Tide objects (a separate RFC) |

## 4. The Tide block: `platform::datadog::1.0`

### 4.1 Shape

Keys are snake_case, as in every other block. Durations are strings (`5m`, `1h`, `1d`), checked
against the values Datadog accepts. The compiler writes the camelCase API body (section 6).

```yaml
name: Okta brute force followed by a successful login
metadata:
  uuid: 2b0d7c1e-0b55-4f0e-9d0b-3c0f2a8f9a11
  schema: rule::1.0
  version: 1
  created: "2026-11-26"
  modified: "2026-11-26"
  tlp: clear
  author: Detection Engineering
description: |
  One user fails to log in to Okta more than ten times in five minutes,
  then logs in successfully.
techniques:
  - T1110.001
response:
  alert_severity: High
configurations:
  datadog:
    schema: platform::datadog::1.0
    enabled: true
    status: STAGING
    type: log_detection            # | signal_correlation
    detection: threshold           # | new_value | anomaly_detection | impossible_travel
    queries:
      - name: failed
        query: |
          source:okta @evt.name:user.session.start @evt.outcome:FAILURE
        group_by: ["@usr.email"]
      - name: success
        query: |
          source:okta @evt.name:user.session.start @evt.outcome:SUCCESS
        group_by: ["@usr.email"]
    cases:
      - name: brute force then success
        condition: failed > 10 && success > 0
        # severity: high           # default: response.alert_severity
        notifications: [soc]       # aliases from the tenant, or raw @handles
    window: 5m                     # evaluationWindow
    keep_alive: 1h
    max_signal_duration: 1d
    group_signals_by: ["@usr.email"]
    decrease_severity_outside_production: true   # decreaseCriticalityBasedOnEnv
    #message: |                    # default: derived from the rule (6.3)
    #tags: ["team:identity"]
```

### 4.2 Keys

| Key | Type | Default | API field | Notes |
|---|---|---|---|---|
| `schema` | `platform::datadog::1.0` | required | — | |
| `enabled`, `status`, `name`, `flags`, `tenants`, `contributors` | as every block | | | `status` drives the modifiers and strategies as elsewhere |
| `type` | `log_detection` \| `signal_correlation` | `log_detection` | `type` | Other API types are refused (`datadog_type_unsupported`) |
| `detection` | enum | `threshold` | `options.detectionMethod` | `sequence_detection`, `third_party` and `hardcoded` are refused in 1.0 |
| `queries[]` | list, 1 to 10 **(unverified upper bound)** | required | `queries` | |
| `queries[].name` | `[a-z][a-z0-9_]*` | `a`, `b`, … by position | `name` | Terraform: not compatible with `new_value` aggregation |
| `queries[].query` | Datadog search syntax, profile `rule` | required for `log_detection` | `query` | |
| `queries[].data_source` | `logs` \| `audit` \| `events` \| `security_signals` | `logs` | `dataSource` | `spans`, `network`, `security_runtime` later |
| `queries[].aggregation` | `count` \| `cardinality` \| `sum` \| `max` \| `new_value` \| `geo_data` \| `none` | follows `detection` | `aggregation` | `event_count` is implied for `signal_correlation` |
| `queries[].group_by[]` | facet paths | `[]` | `groupByFields` | Checked as field paths |
| `queries[].distinct[]` | facet paths | `[]` | `distinctFields` | `cardinality` only |
| `queries[].metrics[]` | facet paths | `[]` | `metrics` | Exactly one for `sum`, `max` and `geo_data`; one to five for `new_value` |
| `queries[].optional_group_by` | bool | `false` | `hasOptionalGroupByFields` | |
| `queries[].rule` | a Tide rule UUID | — | `ruleId` (resolved) | `signal_correlation` only (section 4.4) |
| `queries[].rule_id` | a Datadog rule id | — | `ruleId` | `signal_correlation` only; for rules opentide does not own, defaults included |
| `queries[].correlate_by[]` | facet paths | — | `correlatedByFields` | `signal_correlation` only |
| `cases[]` | list, at least one | required | `cases` | Evaluated in order; the first match wins |
| `cases[].condition` | condition grammar (4.5) | required unless `new_value` or `impossible_travel` | `condition` | |
| `cases[].severity` | `info` \| `low` \| `medium` \| `high` \| `critical` | from `response.alert_severity` | `status` | |
| `cases[].notifications[]` | tenant alias or `@handle` | `[]` | `notifications` | |
| `window` | one of `0`, `1m`, `5m`, `10m`, `15m`, `30m`, `1h`, `2h`, `3h`, `6h`, `12h`, `1d` | `5m` | `options.evaluationWindow` (s) | The same set for the next two |
| `keep_alive` | same set | `1h` | `options.keepAlive` | `window` ≤ `keep_alive` |
| `max_signal_duration` | same set | `1d` | `options.maxSignalDuration` | `window` ≤ `max_signal_duration` |
| `group_signals_by[]` | facet paths | — | `groupSignalsBy` | A subset of every query's `group_by` |
| `extended_title` | bool | `true` | `hasExtendedTitle` | |
| `decrease_severity_outside_production` | bool | `false` | `options.decreaseCriticalityBasedOnEnv` | `log_detection` only |
| `new_value` | `{forget_after: 1d..30d, learning: 0d..30d, learning_method: duration \| threshold, learning_threshold: 0 \| 1}` | — | `options.newValueOptions` | Only with `detection: new_value` |
| `anomaly` | `{bucket: 5m \| 10m \| 15m \| 30m \| 1h \| 3h, learning: 1h \| 6h \| 12h \| 1d \| 2d \| 7d \| 14d, tolerance: 1..5}` | — | `options.anomalyDetectionOptions` | Only with `detection: anomaly_detection` |
| `impossible_travel` | `{baseline_user_locations: bool, baseline_duration: 1d..30d, detect_ip_transition: bool}` | — | `options.impossibleTravelOptions` | At least one of the two booleans is true; the query's aggregation is `geo_data` on `@network.client.geoip` |
| `message` | Markdown with Datadog template variables | derived (6.3) | `message` | |
| `tags[]` | Datadog tags | `[]` | `tags` | Added to the derived tags (6.4) |

### 4.3 Constraint codes (the block)

Each is its own finding at its own field path, as `graylog_constraints` reports them.

| Code | Finding |
|---|---|
| `datadog_type_unsupported` | `type` or `detection` outside the 1.0 scope |
| `datadog_sql_unsupported` | A query asks for `query_language: sql` |
| `datadog_duration` | `window`, `keep_alive`, `max_signal_duration` or an option duration outside the allowed set |
| `datadog_window_order` | `window` greater than `keep_alive` or `max_signal_duration` |
| `datadog_query_name` | A query name that is not `[a-z][a-z0-9_]*`, a duplicate, or a name on a `new_value` query |
| `datadog_aggregation` | An aggregation that does not fit the detection method, or the wrong number of `metrics` or `distinct` fields for it |
| `datadog_detection_options` | An option block (`new_value`, `anomaly`, `impossible_travel`) that does not match `detection`, or is missing |
| `datadog_group_signals_by` | `group_signals_by` not a subset of the queries' `group_by` |
| `datadog_correlation` | A `signal_correlation` query without exactly one of `rule` and `rule_id`, or with a `query`; or a `log_detection` query with either |
| `datadog_condition` | A case condition that does not parse, names an unknown query, puts the number first (`3 < a`), or uses an operator the method does not allow (anomaly: `>`, `>=`, `&&`, `\|\|` only) |
| `datadog_severity` | A case severity outside the five Datadog statuses |
| `datadog_notification_alias` | A notification alias the tenant does not define (deploy time) |
| `datadog_tag` | A tag Datadog would refuse or rewrite: more than 200 characters, upper case, or a character outside `[a-z0-9_\-:./]` |

### 4.4 Signal correlation across Tide rules

A `signal_correlation` query can name a **Tide rule** by UUID. Deploy resolves it to the Datadog
rule id that `.opentide/states/deployment/` holds for the same tenant, and deploys the referenced
rule first. A reference to a rule that is not deployed to that tenant fails the correlation rule
(`datadog_correlation_unresolved`), never the whole run. `rule_id` takes a raw Datadog id for rules
opentide does not own, such as Datadog's own default rules.

```yaml
configurations:
  datadog:
    schema: platform::datadog::1.0
    type: signal_correlation
    queries:
      - name: bruteforce
        rule: 2b0d7c1e-0b55-4f0e-9d0b-3c0f2a8f9a11   # a Tide rule
        correlate_by: ["@usr.email"]
      - name: mfa_reset
        rule_id: def-000-xyz                           # a Datadog rule (illustrative id)
        correlate_by: ["@usr.email"]
    cases:
      - condition: bruteforce > 0 && mfa_reset > 0
        severity: critical
    window: 15m
```

### 4.5 The condition grammar

```text
condition  = or_expr
or_expr    = and_expr ( "||" and_expr )*
and_expr   = comparison ( "&&" comparison )*
comparison = query_name ( ">" | ">=" | "<" | "<=" ) number
query_name = [a-z][a-z0-9_]*
number     = [0-9]+ ( "." [0-9]+ )?
```

The query name comes first: Datadog's docs say `a > 3` is allowed and `3 < a` is not. `<` and `<=`
are documented for threshold rules only. Whether `&&` binds tighter than `||`, and whether
parentheses are accepted, is **unverified**. Until a tenant settles it, the checker refuses a
condition that mixes `&&` and `||` without the clauses being one kind. This is the same
conservative choice Exabeam's `exabeam_mixed_boolean` makes.

## 5. The language: Datadog search syntax (`datadog`)

### 5.1 Name and profiles

| Item | Value |
|---|---|
| Language id | `datadog` (`LanguageId::Datadog`); open question 1 weighs `ddsearch` instead |
| Crate | `opentide-datadog`, foundation tier 2, beside `opentide-cql` |
| File suffix | `.datadog` |
| Code prefix | `datadog_` |
| Profile `rule` | `queries[].query` of a block: no `*:` full-text search (Datadog lists the contexts that refuse it; SIEM is not listed, so this is a warning until verified) |
| Profile `search` | `.datadog` files, hunts with `system: datadog`, `opentide query`: `*:` allowed |

### 5.2 Why a new crate, not a Lucene dialect

`opentide-lucene` already serves three dialects (Elastic, Carbon Black, Graylog), and the
Datadog syntax looks like Lucene. But the differences reach the tree, not just the diagnostics:

| | Lucene classic (`opentide-lucene`) | Datadog search syntax |
|---|---|---|
| Precedence | None: `a OR b AND c` is `a +b +c` | `AND` (explicit or implied) binds tighter than `OR` (VRL's grammar, pySigma's backend) |
| Fields | `field:value` | `@attribute.path:value` for attributes; bare `key:value` for tags and the reserved attributes (`host`, `source`, `status`, `service`, `trace_id`, `message`); `#name` for calculated fields |
| Negation | `NOT`, `-`, `!` | `-` and `NOT` (`!`, `&&`, `\|\|` are escaped characters; their status as operators is unverified) |
| Functions | none | `CIDR(@attr, block, …)` |
| Wildcards | `*`, `?` within a term | `*` within a word, `**` across words, `\ ` to join words, `?` for one special character or space; ignored inside quotes |
| Regex, fuzzy, boost | `/re/`, `~`, `^` | none |
| Free text | the default field | `message`, `@title`, `@error.message`, `@error.stack` only; `*:term` searches every attribute |
| Tokenising | analyser dependent | Unicode word boundaries (`version.2` is two words, `my.friend` one) |

A dialect flag would make the walk branch on the dialect at every node, and the precedence
difference changes the tree's shape. The rule set in the [add-language
skill](../../.agents/skills/add-language/SKILL.md) applies unchanged: a logos lexer, a hand-written
Pratt grammar on `opentide-parse`, a lossless rowan tree, `src/datadog.ungram` and the depth
contract.

### 5.3 Grammar (first draft of `datadog-1.0`)

```text
query       = or_expr?
or_expr     = and_expr ( "OR" and_expr )*
and_expr    = unary ( "AND"? unary )*                 // juxtaposition is AND
unary       = ( "-" | "NOT" | "+" ) unary | primary
primary     = "(" or_expr ")"
            | cidr_call
            | field ":" value
            | field ":" "(" value_expr ")"
            | value                                   // free text
cidr_call   = "CIDR" "(" attribute ( "," cidr_block )+ ")"
field       = attribute | tag_key | calculated
attribute   = "@" path
calculated  = "#" path
tag_key     = path                                    // reserved attributes and tags
path        = SEGMENT ( "." SEGMENT )*
value       = PHRASE | comparison | range | TERM | WILDCARD_TERM | "*"
comparison  = ( ">" | ">=" | "<" | "<=" ) TERM
range       = ( "[" | "{" ) bound "TO" bound ( "]" | "}" )
bound       = TERM | "*"
value_expr  = value_or                                // a group inside field:( … )
value_or    = value_and ( "OR" value_and )*
value_and   = value_unary ( "AND"? value_unary )*
value_unary = ( "-" | "NOT" ) value_unary | "(" value_expr ")" | value
```

Lexing rules:

- **Phrases.** A phrase is straight-double-quoted, with `\X` escapes.
- **Terms.** A term may not start with `( ) [ ] { } " : - ! ~ ^ ? * \ > = <` or whitespace.
- **Escapes.** A backslash escapes any one character. The escape set Datadog lists is
  ``- ! && || > >= < <= ( ) { } [ ] " * ? : \ #`` and space; `/` is not special.
- **Numbers** follow VRL's `-?\d+(\.\d+)?(E-?\d+(\.\d+)?)?`.
- **Operators.** `AND`, `OR`, `NOT` and `TO` are operators only in upper case.

### 5.4 Diagnostics (first draft)

| Code | Severity | Fires on |
|---|---|---|
| `datadog_parse_error` | error | Unbalanced parentheses or brackets, a dangling operator, an empty group, `field:` without a value |
| `datadog_lowercase_operator` | warning | `and`, `or`, `not` or `to` between clauses: they are search terms |
| `datadog_curly_quote` | warning | `“…”`: Datadog ignores curly quotes, so the phrase becomes separate terms |
| `datadog_wildcard_in_phrase` | warning | `"*test*"`: wildcards inside quotes are punctuation in Log Explorer |
| `datadog_unescaped_special` | error | An unescaped special character inside a term (`@a:b:c`, `@url:/api-v1/*` where `-` begins a word) |
| `datadog_cidr` | error | `CIDR` with no attribute, a tag instead of an `@attribute`, or a block that is not an IPv4 or IPv6 CIDR |
| `datadog_range` | error | Mixed bounds `[a TO b}`, a lower-case `to`, a comparison on a phrase (mixed bounds unverified) |
| `datadog_mixed_boolean` | warning | `a OR b c`, where the implied AND binds tighter than the OR it sits beside; suggest parentheses |
| `datadog_full_text_in_rule` | warning | `*:term` in profile `rule` |
| `datadog_regex` | error | `~` or `^` in a term: Datadog has no fuzzy or boost operators, and no regex (`/` is an ordinary character, so `@http.url:/api` is a path, not a regex) (pySigma's backend refuses `\|re` for the same reason) |
| `datadog_unknown_attribute` | hint | An `@attribute` that neither the standard attributes nor the source's pipeline catalog knows (section 5.6) |

### 5.5 Highlighting (existing captures only)

No capture is added to `highlights/spec.toml`.

| Token | Example | Capture |
|---|---|---|
| Attribute path | `@evt.outcome` | `property` |
| Tag key or reserved attribute | `source`, `env`, `service` | `property` |
| Calculated field | `#duration_ms` | `variable` |
| Field separator | `:` | `operator` |
| Comparison | `>`, `>=`, `<`, `<=` | `operator` |
| Exclusion | `-` (prefix) | `operator` |
| Boolean | `AND`, `OR`, `NOT` | `keyword` (TextMate: `keyword.operator.logical`, as Lucene's `tm_extras:logical`) |
| Range keyword | `TO` | `keyword` |
| `CIDR` | `CIDR(` | `function.builtin` |
| CIDR block, IP | `10.0.0.0/8` | `constant` |
| Phrase | `"hello world"` | `string` |
| Number | `400`, `0.95` | `number` |
| Wildcard | `*`, `**`, `?` | `operator` |
| Escape | `\:` | `constant` |
| Brackets | `( ) [ ] { }` | `punctuation.bracket` |
| Comma | `,` | `punctuation.delimiter` |
| Error node | | `error` |

In conditions, query names are `variable`, comparisons and `&&`/`||` are `operator`, and numbers
are `number`. In `message`, the Markdown stays Markdown and `{{…}}` template variables are
`macro` (an existing capture). The YAML wiring to add:

- `platform_field_language` (`crates/opentide-tide/src/lib.rs`): `PlatformId::Datadog` answers
  `["queries", <index>, "query"]`, exactly as Exabeam answers `["sequences", <index>, "query"]`.
  Validation, the language server and semantic tokens then cover every rule query.
- `EMBEDDED_QUERIES` (the TextMate injection, `crates/opentide-highlight/src/lib.rs`) lists only
  fixed key paths, and Exabeam's list-item queries are not in it. Datadog starts the same way:
  semantic tokens colour the queries, and a list-item TextMate injection for both platforms is a
  follow-up.

### 5.6 Catalogs

| Catalog | Source | Licence | Holds |
|---|---|---|---|
| Reserved and standard attributes | docs.datadoghq.com/standard-attributes (default list) | facts only; summaries written here (ADR 0013) | `@network.client.ip`, `@usr.email`, `@evt.name`, `@evt.outcome`, `@http.status_code`, … with types |
| Source pipelines | DataDog/integrations-core `*/assets/logs/*.yaml` (the Datadog log pipelines and their test samples, 408 files) | BSD-3-Clause | `source:` values, and each source's remapped attribute paths, for completion and `datadog_unknown_attribute` |
| Template variables | docs.datadoghq.com/security/notifications/variables | facts only | `{{severity}}`, `{{rule_name}}`, `{{events_matched}}`, `{{@attr}}`, `{{#is_match}}`, … |

## 6. Compiling a block (deploy body)

### 6.1 Mapping

| Tide | Datadog body |
|---|---|
| `name` | `name` |
| block `enabled` and the status strategy | `isEnabled` |
| `type`, `detection` | `type`, `options.detectionMethod` |
| `queries[]` | `queries[]`, camelCase. `rule` is resolved to `ruleId` (4.4), and `aggregation` defaults by method: `count` for threshold, `new_value` for new value, `geo_data` plus `metrics: ["@network.client.geoip"]` for impossible travel, `event_count` for correlation |
| `cases[]` | `cases[]`. `severity` (or `response.alert_severity` mapped Informational→`info`, Low→`low`, Medium→`medium`, High→`high`, Critical→`critical`) becomes `status`; notification aliases are resolved |
| durations | seconds |
| `message` | the block's, else derived (6.3) |
| tags | derived (6.4), plus the block's and the tenant's |

### 6.2 Example body

The example in 4.1 compiles to:

```json
{
  "name": "Okta brute force followed by a successful login",
  "type": "log_detection",
  "isEnabled": true,
  "queries": [
    {"name": "failed", "query": "source:okta @evt.name:user.session.start @evt.outcome:FAILURE",
     "dataSource": "logs", "aggregation": "count", "groupByFields": ["@usr.email"], "distinctFields": []},
    {"name": "success", "query": "source:okta @evt.name:user.session.start @evt.outcome:SUCCESS",
     "dataSource": "logs", "aggregation": "count", "groupByFields": ["@usr.email"], "distinctFields": []}
  ],
  "cases": [
    {"name": "brute force then success", "status": "high",
     "condition": "failed > 10 && success > 0", "notifications": ["@slack-soc-alerts"]}
  ],
  "options": {"detectionMethod": "threshold", "evaluationWindow": 300, "keepAlive": 3600,
              "maxSignalDuration": 86400, "decreaseCriticalityBasedOnEnv": true},
  "groupSignalsBy": ["@usr.email"],
  "hasExtendedTitle": true,
  "message": "## Goal\nOne user fails to log in to Okta more than ten times in five minutes, then logs in successfully.\n\n## Strategy\n…",
  "tags": ["source:okta", "tactic:TA0006-credential-access", "technique:T1110-brute-force",
           "security:attack", "opentide_uuid:2b0d7c1e-0b55-4f0e-9d0b-3c0f2a8f9a11"]
}
```

### 6.3 The derived message

Datadog's own rules use `## Goal`, `## Strategy` and `## Triage and response` sections. The
derived message follows them:

- `## Goal` from `description`.
- `## Strategy` from the queries and cases, in words.
- `## Triage and response` from `response.procedure`.

Text from the rule is escaped so that `{{` in a description is not read as a template.

### 6.4 Derived tags

The derived tags follow Datadog's own conventions:

- `source:<x>` for each distinct `source:` the queries name.
- `tactic:<TA id>-<slug>` and `technique:<T id>-<slug>` from `techniques`, taking the parent
  technique for a sub-technique, as Datadog's default rules do.
- `security:attack`.
- `opentide_uuid:<uuid>`, which lets deploy and `doctor` find the rules opentide owns.

All are lower-cased and checked against `datadog_tag`.

## 7. The connector

### 7.1 Tenant (`platforms/datadog.toml`)

```toml
[platform]
enabled = false
name = "Datadog Cloud SIEM"
description = "Datadog Cloud SIEM detection rules (log detection and signal correlation)."

# Datadog Cloud SIEM through the v2 Security Monitoring API. site is the Datadog site
# (datadoghq.com, us3.datadoghq.com, us5.datadoghq.com, datadoghq.eu, ap1.datadoghq.com,
# ap2.datadoghq.com, uk1.datadoghq.com, ddog-gov.com, us2.ddog-gov.com); calls go to
# https://api.<site>. api_key and app_key are sent as DD-API-KEY and DD-APPLICATION-KEY.
# The application key needs security_monitoring_rules_read and security_monitoring_rules_write
# (validate needs write), and logs_read_data for opentide query. Use a service account's
# scoped key. The rule id is kept in .opentide/states/deployment/ (commit it).
#[[tenants]]
#name = "datadog-eu"
#strategies = ["RELEASE"]
#[tenants.setup]
#site = "datadoghq.eu"
#api_key = "$DD_API_KEY"
#app_key = "$DD_APP_KEY"
#tags = ["managed-by:opentide"]
#[tenants.setup.notifications]
#soc = "@slack-soc-alerts"
```

### 7.2 Calls

Every path is under `https://api.<site>/api/v2/security_monitoring`. All are GA.

| opentide | Call | Scope | Result handling |
|---|---|---|---|
| `validate query --live`, `deploy` pre-check | `POST /rules/validation` with the compiled body | `security_monitoring_rules_write` | 204 means valid; 400 gives `datadog_rule_invalid` with Datadog's `errors[]` |
| deploy, new rule | `POST /rules` | `…_rules_write` | 200 with the rule; `id` and `version` go to the deployment state |
| deploy, existing rule | `PUT /rules/{id}`, sending `queries`, `cases` and `options` whole | `…_rules_write` | The spec maps a concurrent modification to **401**: report `datadog_concurrent_modification` and do not treat it as an authentication failure |
| `DISABLEMENT` | `PUT /rules/{id}` with `isEnabled: false` | `…_rules_write` | |
| `DELETION` | `DELETE /rules/{id}` | `…_rules_write` | 204; a 404 is `datadog_rule_missing` (already gone) |
| drift, `doctor` | `GET /rules/{id}` | `…_rules_read` | Compare `version` with the stored one; `GET /rules/{id}/version_history` names who changed what |
| `opentide query` | `POST /api/v2/logs/events/search` with `filter.query`, `from`, `to`, `indexes`, `storage_tier` | `logs_read_data` | Cursor paging through `meta.page.after`, up to 5,000 events a page |
| later: rule tests | `POST /rules/test` with `ruleQueryPayloads` | `…_rules_write` | `results[]`, one bool per sample |

### 7.3 Failure codes

| Code | When |
|---|---|
| `datadog_tenant_unauthorized` | A 403, or a 401 that is not a concurrent modification |
| `datadog_tenant_unreachable` | DNS, TLS or a timeout |
| `datadog_site` | A `site` outside the known list |
| `datadog_rate_limited` | A 429; retried after `X-RateLimit-Reset` |
| `datadog_rule_invalid` | A 400 from `/rules/validation` or a write |
| `datadog_rule_missing` | The stored id is gone |
| `datadog_rule_recreated` | The stored id was gone and deploy created a new one |
| `datadog_rule_default` | The stored id is a default rule (`isDefault: true`): opentide never overwrites or deletes one |
| `datadog_correlation_unresolved` | A correlation `rule` not deployed to the tenant |

The external id is Datadog's rule id. Every example seen is three groups of three lower-case
alphanumerics (`m0o-hto-lkb`, `def-000-u7q`), so the registry's `IdPattern` is proposed as
`[a-z0-9]{3}-[a-z0-9]{3}-[a-z0-9]{3}` **(unverified: no source states the format)**.

## 8. Wiring (where the implementation lands)

| Area | Files |
|---|---|
| Registry row | `crates/opentide-schema/src/platforms.rs` (`id: "datadog"`, `deploys`, `compiles_offline`, `live_check`, `query_runner`, `runner_languages: &["datadog"]`, `offline_languages: &["datadog"]`, `query_file_suffixes: &["datadog"]`) |
| Model and constraints | `crates/opentide-schema/src/objects/platform/datadog.rs`, `datadog/condition.rs`; `platform/mod.rs` registration; `schema.rs` required keys |
| Template | `src/opentide/schemas/data/platform_templates/datadog.template.yaml`; `src/opentide/data/configurations/platforms/datadog.toml` |
| Compiler | `crates/opentide-compile/src/datadog.rs`, `modifiers.rs`, `preview.rs`, the platform docs generator |
| Connector | `crates/opentide-connectors/src/datadog.rs` (+ the fake-API tests and cassettes) |
| Engine | `crates/opentide-datadog/`; `opentide-core` `LanguageId::Datadog` and codes; `opentide-highlight` keywords and `EMBEDDED_QUERIES`; `opentide-tide` `platform_field_language` and hunt `system: datadog`; `opentide-analysis` queries; fuzz target; corpus |
| Command line and MCP | `new`, `setup --datadog`, `doctor`, `query`, `validate_live`, MCP `validate_query`/`run_query` lists |
| Diagnostics pages | `src/opentide/data/diagnostics/datadog_*.md` |
| Docs | the seven pages named in `AGENTS.md` "Platforms", plus `docs/engine/DATADOG.md` |
| Companion | opentidehq/skills: a Datadog platform skill and `coverage.json` |

`cargo test -p xtask --test language_wiring` and `xtask/tests/platform_docs.rs` list whatever is
missing.

## 9. Open-source content to start from

There is **no sizeable open corpus of Datadog Cloud SIEM rules in Datadog's own format**.

- **Datadog's built-in rules.** The catalog (docs.datadoghq.com/security/default_rules, about 970
  Cloud SIEM rules) publishes each rule's Goal, Strategy and Triage text, but not its queries. The
  site's source data is private. A machine-readable copy needs an account: the API (`isDefault:
  true`) or Terraform's `datadog_security_monitoring_default_rule`.
- **Datadog's own detection-as-code repository** is internal (per its 2024 blog post).

What exists, ranked by use:

| Source | Licence | What it gives | Use |
|---|---|---|---|
| [DataDog/integrations-core](https://github.com/DataDog/integrations-core) and [integrations-extras](https://github.com/DataDog/integrations-extras): log saved views (135, 169 unique queries), `logs("…")` monitors (31), pipeline test fixtures (`assets/logs/`, 408 files) | BSD-3-Clause | Real Datadog search queries written by Datadog, sources and attribute remaps, sample logs | **(a) Conformance corpus**, vendored with the notice. Catalogs (5.6). Sample events for `POST /rules/test` |
| integrations-extras `*/assets/security/*.json` (AppOmni, Bottomline, Contrast: 11 rules) | BSD-3-Clause | The only permissively licensed rules already in Datadog's export format: threshold, impossible travel, anomaly and third party | **API body fixtures** and **(b) seed rules** |
| [terraform-provider-datadog](https://github.com/DataDog/terraform-provider-datadog) test cassettes `TestAccDatadogSecurityMonitoringDefaultRule_*.yaml` | MPL-2.0 files, recording Datadog's proprietary rule content | 199 recorded built-in rules: 82 `log_detection` with 122 unique queries (67 CloudTrail, Microsoft 365, 1Password, Kubernetes audit), real escaping (`system\:serviceaccount\:*`), every detection method | **Measured, not vendored**, as Exabeam's content hub: an ignored test reads a local checkout. The provider's `examples/` and the [datadog-api-client-*](https://github.com/DataDog/datadog-api-client-python) `examples/v2/security-monitoring` (Apache-2.0) give API fixtures |
| [DataDog/documentation](https://github.com/DataDog/documentation) `hugo/content/en/api/v2/security-monitoring/request.*Rule*.json` | to confirm (GitHub reports NOASSERTION) | 42 synthetic API request bodies covering every rule type and detection method | Schema fixtures once the licence is confirmed; until then, a reference only |
| [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | DRL 1.1 (MIT-like; keep `author` and the licence, also in alert messages) | 3,807 rules; about 280 cloud and SaaS (AWS 58, Azure 123, GCP 26, M365 19, Okta 21, GitHub 15, Kubernetes 16, Bitbucket 14) | **(b) Seed rules**, converted by **our own** Sigma-to-Tide mapping into Datadog's attribute names (`@evt.name`, `@userIdentity.arn`), keeping the Sigma id, author and a DRL link in the rule and its derived message |
| [SigmaHQ/pySigma-backend-datadog](https://github.com/SigmaHQ/pySigma-backend-datadog) | LGPL-3.0 | A small converter (about 230 lines): `@` prefixes every field, maps three log sources, no regex, no aggregations. Pre-release; pins pySigma `^0.11`, which current Sigma rules break (current pySigma is 2.x) | A reference and a **robustness corpus**, never a dependency or golden truth (below) |
| [vectordotdev/vrl](https://github.com/vectordotdev/vrl) `src/datadog/search/` | MPL-2.0 | Datadog's own pest grammar for the search syntax, with its tests | The grammar reference and a **differential oracle** (`scripts/engine/oracles/datadog/`): run VRL over the corpus and compare accept and reject verdicts. Not vendored |
| [DataDog/stratus-red-team](https://github.com/DataDog/stratus-red-team) (103 techniques, 36 detonation logs), [grimoire](https://github.com/DataDog/grimoire), [threatest](https://github.com/DataDog/threatest) | Apache-2.0 | Attack, recorded logs, and an assertion that the Datadog signal fired | Seed rules written against Stratus techniques, with the detonation logs as their `POST /rules/test` samples; a manual tenant run like `microsoft-defender-tenant-test.md` |
| [DataDog/security-agent-policies](https://github.com/DataDog/security-agent-policies) | Apache-2.0 | 331 Workload Protection rules in SECL | Out of scope (a different language) |
| Community Terraform (139 files contain `resource "datadog_security_monitoring_rule"`, nearly all docs, forks or tooling; for example grcengineering/how-to-harden, MIT, 7 rules on `source:audit`) | mixed; several have no licence | Tiny sets | Only MIT or Apache-2.0 ones, as examples; never an unlicensed repository |
| panther-analysis (Apache-2.0), splunk/security_content (Apache-2.0), Azure-Sentinel (MIT), elastic/detection-rules (Elastic License 2.0) | as listed | Rules in other languages | Ideas for coverage, not content; nothing from ELv2 |

### 9.1 What the prototype checker already shows

The tokenizer prototype in the technical artifact implements sections 5.3 to 5.5. It was run over
two corpora on 2026-11-26:

- **The 153 unique queries of the recorded built-in rules** (122 from log detection rules, the
  rest posture queries). Every query parsed, and the tokens cover the text exactly. There is one
  finding, and it is real: a Microsoft 365 rule lists file types as
  `@SourceFileName:(*.exe OR … OR *.zip OR *.rar *.7z *.cab OR *.tar …)`. Datadog documents a space
  inside a value group as AND (`@user_perms:(4 6)` means both). With AND binding tighter than OR,
  `*.rar *.7z *.cab` asks for a file name ending in all three at once, which never happens, so
  `.rar`, `.7z` and `.cab` uploads go undetected.
  That is `datadog_mixed_boolean`, as designed. It also makes open question 2 worth settling on a
  tenant first.
- **1,411 Sigma rules converted by pySigma-backend-datadog.** 39 queries have at least one finding
  (32 with `datadog_parse_error`, 24 with `datadog_mixed_boolean`, 3 with
  `datadog_wildcard_in_phrase`; some have several). The samples
  inspected trace to the backend's own output: an empty value (`@DeviceDetail.trusttype: OR …`),
  `\\"` escaping, and its `-@field:[0* TO z*] AND @field:*` null check placed inside an OR group
  without parentheses. Its `siem_rule` format also prepends `source:gcp ` to an OR without
  parentheses. Hence our own conversion for seed rules.

## 10. Plan

| Phase | Delivers | Exit criteria |
|---|---|---|
| 0. Specs | This RFC numbered in opentidehq/specifications; `datadog-1.0` language and platform specs with fixtures; an issue per phase | Specs reviewed; open questions 2 to 6 answered on a trial tenant |
| 1. Engine | `opentide-datadog`: lexer, Pratt grammar, `.ungram`, profiles, diagnostics, highlight, catalogs, corpus gate, VRL differential, fuzz target, throughput budget | `language_wiring` green; the integrations corpus clean; the recorded built-in rules measured with every finding explained; VRL agreement measured and explained |
| 2. Platform | Model, constraints, compiler, connector (validate, deploy, disable, delete, drift), registry row, `setup --datadog`, docs, explain pages, snapshots | `scripts/ci-local.sh --full`; a tenant run recorded like the Defender one; the skills companion |
| 3. Depth | `opentide query`; rule tests through `/rules/test`; sequence, scheduled and third-party rules; default-rule tuning; message template checks | Each behind its own spec minor version |

## 11. Open questions

1. **The language id.** `datadog`, which follows Exabeam's precedent and is what users search for,
   or `ddsearch`, which leaves room if DDSQL or SECL ever become engine languages? The draft
   picks `datadog`, since SQL is out of scope and SECL belongs to a different product.
2. **Precedence and operators.** Whether Log Explorer and Cloud SIEM bind `AND` tighter than `OR`
   (as VRL does), and whether `&&`, `||` and `!` are operators. To be settled with
   `POST /rules/validation` and `POST /rules/test` on a trial tenant, and recorded as a probe set
   like Graylog's oracle.
3. **Condition grammar.** Whether conditions accept parentheses, `==`, and both `&&` and `||`
   together, and how the UI's "then" condition is serialised.
4. **Rule id format** (7.3) and whether `def-000-` always marks a default rule. Deploy relies on
   `isDefault` either way.
5. **Limits.** The maximum number of queries and cases per rule (historical jobs cap both at 10),
   the query length, and the numeric rate limits for the rules and logs-search endpoints.
6. **`*:` full text, `_exists_`, open and mixed range bounds** in rule queries.
7. **A write-scoped key for validation.** `validate --live` needs
   `security_monitoring_rules_write`. Should `setup` recommend a separate validation key, and should
   `doctor` warn when the key that only validates could also delete?
8. **Suppressions.** Model suppression rules (`/configuration/suppressions`) as part of the block
   (`suppressions[]`, deployed with the rule and tagged `ruleId:<id>`, as Datadog's own team does)
   or as their own Tide object.

## 12. References

- API reference: https://docs.datadoghq.com/api/latest/security-monitoring/
- OpenAPI v2 (the `x-unstable` marker means preview): https://github.com/DataDog/datadog-api-client-python/blob/master/.generator/schemas/v2/openapi.yaml
- Log search syntax: https://docs.datadoghq.com/logs/explorer/search_syntax/
- Creating rules, conditions: https://docs.datadoghq.com/security/cloud_siem/detect_and_monitor/custom_detection_rules/create_rule/
- Sequence rules: https://docs.datadoghq.com/security/cloud_siem/detect_and_monitor/custom_detection_rules/sequence/
- Suppressions: https://docs.datadoghq.com/security/cloud_siem/detect_and_monitor/suppressions/
- Notification variables: https://docs.datadoghq.com/security/notifications/variables/
- Calculated-field formulas: https://docs.datadoghq.com/logs/explorer/calculated_fields/formulas/
- DDSQL: https://docs.datadoghq.com/ddsql_reference/
- Sites: https://docs.datadoghq.com/getting_started/site/
- API and application keys: https://docs.datadoghq.com/account_management/api-app-keys/
- Rate limits: https://docs.datadoghq.com/api/latest/rate-limits/
- Logs search: https://docs.datadoghq.com/api/latest/logs/search-logs-post.md
- Terraform: https://registry.terraform.io/providers/DataDog/datadog/latest/docs/resources/security_monitoring_rule
- Detection as code for Cloud SIEM (2025-06-11): https://www.datadoghq.com/blog/detection-as-code-cloud-siem/
- How Datadog uses detection as code (2024-10-11): https://www.datadoghq.com/blog/datadog-detection-as-code/
- VRL Datadog search grammar: https://github.com/vectordotdev/vrl/tree/main/src/datadog/search
- pySigma Datadog backend: https://github.com/SigmaHQ/pySigma-backend-datadog
