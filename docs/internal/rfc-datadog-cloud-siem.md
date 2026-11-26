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
> YAML shape, the highlighting and a working prototype of the lexer and checks of sections 4.6 and
> 5.3 to 5.6; section 9.1 has what that prototype found in real queries.

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
| Detection methods `threshold`, `new_value`, `anomaly`, `impossible_travel` | Scheduled rules (`schedulingOptions`, an RFC 5545 RRULE), `calculatedFields` (a formula language) | `application_security`, `api_security` (App and API Protection, ASM actions) |
| `type: signal_correlation`, referencing Tide rules or Datadog rule ids | `third_party` (`thirdPartyCases`, `rootQueries`) | `cloud_configuration`, `infrastructure_configuration` (CSPM, Rego) |
| `dataSource` `logs` (default), `audit`, `events`, `security_signals` | Reference tables (`referenceTables`) | `queryLanguage: sql` (DDSQL): SQL stays unsupported in opentide; a block that asks for it is refused with `datadog_sql_unsupported` |
| Live validation, deploy, disable, delete, drift by `version` | Tuning a Datadog default rule (`customQueryExtension`, `customStatus`, notifications), like Sysdig's `append_to_rule` | `hardcoded` (one value, `log4shell`, Datadog-owned) |
| `opentide query` over the Logs Search API | Rule tests through `POST /rules/test`; backtests through historical jobs (preview) | Suppression rules and security filters as their own Tide objects (a separate RFC) |

## 4. The Tide block: `platform::datadog::1.0`

### 4.1 Shape

Keys are snake_case, as in every other block. Durations are strings (`5m`, `1h`, `1d`), checked
against the values Datadog accepts. The compiler writes the camelCase API body (section 6).

The block does not copy the API's layout. It groups keys by what they mean to the person writing
the rule, as Datadog's own rule editor does:

- `queries` are what to look at.
- `detection` is how the queries become a match: the method, the sliding window the cases are
  tested over, and the method's own settings.
- `cases` are when a match becomes a signal, and at what severity.
- `signal` is what happens to a signal once it exists: how signals are grouped, how long one stays
  open, and how its severity is adjusted.

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
    type: log_detection              # | signal_correlation
    queries:
      - name: failed
        query: |
          source:okta @evt.name:user.session.start @evt.outcome:FAILURE
        group_by: ["@usr.email"]
      - name: success
        query: |
          source:okta @evt.name:user.session.start @evt.outcome:SUCCESS
        group_by: ["@usr.email"]
    detection:
      method: threshold              # default
      window: 5m                     # the cases are tested over the last 5 minutes
    cases:
      - name: brute force then success
        condition: failed > 10 && success > 0
        # severity: high             # default: response.alert_severity
        notify: [soc]                # tenant aliases or raw @handles
    signal:
      group_by: ["@usr.email"]       # one signal per user
      keep_alive: 1h                 # stays open while matches keep arriving within 1h
      max_duration: 1d               # and closes after 1d regardless
      downgrade_non_production: true # one level lower when env starts with staging, test or dev
    #message: |                      # default: derived from the rule (6.3)
    #tags: ["team:identity"]
```

The same rule written to the API's layout would put `evaluationWindow`, `keepAlive`,
`maxSignalDuration` and `decreaseCriticalityBasedOnEnv` side by side in `options`, beside
`newValueOptions` and `impossibleTravelOptions`, and `groupSignalsBy` at the top level. They
answer different questions. In Datadog's docs, the evaluation window is "a sliding period in which
at least one case evaluates as true", while keep alive and maximum signal duration decide when a
signal "remains open" and when it "closes". The block separates them along that line.

### 4.2 Keys

#### Queries

| Key | Type | Default | API field | Notes |
|---|---|---|---|---|
| `queries[]` | list, 1 to 10 **(unverified upper bound)** | required | `queries` | |
| `name` | `[a-z][a-z0-9_]*` | `a`, `b`, … by position | `name` | What conditions call the query; not allowed with `new_value` (Terraform: "not compatible") |
| `query` | Datadog search syntax, profile `rule` | required for `log_detection` | `query` | |
| `from` | `logs` \| `audit` \| `events` \| `signals` | `logs` | `dataSource` (`signals` is `security_signals`) | `spans`, `network`, `security_runtime` later |
| `group_by[]` | field paths | `[]` | `groupByFields` | Each group is counted on its own |
| `keep_missing_groups` | bool | `false` | `hasOptionalGroupByFields` | Events missing a `group_by` value are kept, grouped as `N/A`, instead of dropped |
| `count_distinct` | a field path | — | `aggregation: cardinality`, `distinctFields` | The case counts distinct values instead of events |
| `sum`, `max` | a field path | — | `aggregation: sum` or `max`, `metrics: [field]` | The case compares the sum or the maximum of a numeric field |
| `new_value` | 1 to 5 field paths | — | `aggregation: new_value`, `metrics` | Only with `detection.method: new_value`, where it is required |
| `rule` | a Tide rule UUID or a Datadog rule id | — | `ruleId` (a UUID is resolved, 4.4) | `signal_correlation` only |
| `correlate_by[]` | field paths | — | `correlatedByFields` | `signal_correlation` only |

A query sets at most one of `count_distinct`, `sum`, `max` and `new_value`; with none it counts
events. That replaces the API's `aggregation` enum plus its `distinctFields` and `metrics` lists,
whose valid combinations depend on each other: the measure is named once, with its field.
`geo_data` (impossible travel) and `event_count` (correlation) follow from the rule and are never
written.

#### Detection

| Key | Type | Default | API field | Notes |
|---|---|---|---|---|
| `method` | `threshold` \| `new_value` \| `anomaly` \| `impossible_travel` | `threshold` | `options.detectionMethod` (`anomaly` is `anomaly_detection`) | `sequence`, `third_party` and `content_anomaly` later |
| `window` | one of `0`, `1m`, `5m`, `10m`, `15m`, `30m`, `1h`, `2h`, `3h`, `6h`, `12h`, `1d` | `5m` | `options.evaluationWindow` (seconds) | The sliding window the cases are tested over |
| `learning` | a duration | per method | `newValueOptions.learningDuration` (days, 0 to 30); `anomalyDetectionOptions.learningDuration` (hours: 1h, 6h, 12h, 1d, 2d, 7d, 14d); `impossibleTravelOptions.baselineUserLocationsDuration` (1d to 30d) | How long Datadog learns what is normal before it creates signals. On impossible travel, setting it turns on `baselineUserLocations` |
| `forget_after` | `1d` to `30d` | `7d` | `newValueOptions.forgetAfter` | `new_value`: a learned value is forgotten when it is not seen for this long |
| `bucket` | `5m` \| `10m` \| `15m` \| `30m` \| `1h` \| `3h` | `5m` | `anomalyDetectionOptions.bucketDuration` | `anomaly`: the time bucket the baseline is computed on |
| `tolerance` | 1 to 5 | `3` **(unverified default)** | `anomalyDetectionOptions.detectionTolerance` | `anomaly`: how far above the baseline counts as anomalous |
| `ignore_known_transitions` | bool | `false` | `impossibleTravelOptions.detectIpTransition` | `impossible_travel`: no signal for a move between two locations this user has made before |

`learning` is one key for one idea across three methods; the compiler converts it to the unit each
API field takes, and `datadog_duration` names the values a method accepts.

#### Cases

| Key | Type | Default | API field | Notes |
|---|---|---|---|---|
| `cases[]` | list, at least one | required | `cases` | Tested in order; the first that matches creates the signal |
| `name` | text | — | `name` | |
| `condition` | condition grammar (4.6) | required for `threshold` and `anomaly` | `condition` | |
| `severity` | `info` \| `low` \| `medium` \| `high` \| `critical` | from `response.alert_severity` | `status` | |
| `notify[]` | tenant alias or `@handle` | `[]` | `notifications` | |

#### Signal

| Key | Type | Default | API field | Notes |
|---|---|---|---|---|
| `group_by[]` | field paths | — | `groupSignalsBy` | Matches with the same values update one signal; a subset of the queries' `group_by` |
| `keep_alive` | `window`'s set of durations | `1h` | `options.keepAlive` | The signal stays open while a case matches again within this time; at least `detection.window` |
| `max_duration` | `window`'s set of durations | `1d` | `options.maxSignalDuration` | The signal closes this long after it was first seen, whatever still matches; at least `detection.window` |
| `downgrade_non_production` | bool | `false` | `options.decreaseCriticalityBasedOnEnv` | One severity level lower when the `env` tag starts with `staging`, `test` or `dev`; `log_detection` only |
| `group_in_title` | bool | `false` | `hasExtendedTitle` | The signal's title shows the group-by values |

#### The rest

| Key | Type | Default | API field | Notes |
|---|---|---|---|---|
| `schema` | `platform::datadog::1.0` | required | — | |
| `enabled`, `status`, `name`, `flags`, `tenants`, `contributors` | as every block | | | `status` drives the modifiers and strategies as elsewhere |
| `type` | `log_detection` \| `signal_correlation` | `log_detection` | `type` | Other API types are refused (`datadog_type_unsupported`) |
| `message` | Markdown with Datadog template variables | derived (6.3) | `message` | |
| `tags[]` | Datadog tags | `[]` | `tags` | Added to the derived tags (6.4) |

#### Naming

The names were chosen for the person reading a rule, not for the API:

| API | Block | Why |
|---|---|---|
| `options.detectionMethod` | `detection.method` | |
| `options.evaluationWindow` | `detection.window` | The only window in `detection`, so no qualifier |
| `options.keepAlive` | `signal.keep_alive` | Datadog's own term, and the one its users know; `signal.` says what is kept alive |
| `options.maxSignalDuration` | `signal.max_duration` | `signal.` already says whose duration |
| `options.decreaseCriticalityBasedOnEnv` | `signal.downgrade_non_production` | Says what happens and to which signals; "criticality" is not a word the rest of Tide uses |
| `groupSignalsBy` | `signal.group_by` | The same word as `queries[].group_by`, in the scope it applies to |
| `hasExtendedTitle` | `signal.group_in_title` | Says what the title gains |
| `hasOptionalGroupByFields` | `queries[].keep_missing_groups` | Says what the switch keeps |
| `aggregation` + `distinctFields` / `metrics` | `count_distinct`, `sum`, `max`, `new_value` | One key that names the measure and its field |
| `dataSource` | `from` | Reads as the query's source: `from: audit` |
| `notifications` | `notify` | |
| `ruleId` | `rule` | One key: a UUID is a Tide rule, anything else a Datadog id |

### 4.3 Constraint codes (the block)

Each is its own finding at its own field path, as `graylog_constraints` reports them.

| Code | Finding |
|---|---|
| `datadog_type_unsupported` | `type` or `detection.method` outside the 1.0 scope |
| `datadog_sql_unsupported` | A query asks for SQL (`queryLanguage: sql`) |
| `datadog_duration` | A duration outside the values its key accepts (`detection.window`, `learning`, `forget_after`, `bucket`, `signal.keep_alive`, `signal.max_duration`) |
| `datadog_window_order` | `detection.window` longer than `signal.keep_alive` or `signal.max_duration` |
| `datadog_query_name` | A query name that is not `[a-z][a-z0-9_]*`, a duplicate, or a name on a `new_value` query |
| `datadog_measure` | More than one of `count_distinct`, `sum`, `max` and `new_value`; `new_value` without `method: new_value` or the reverse; more than five `new_value` fields |
| `datadog_detection_option` | A `detection` key that the method does not take (`bucket` on `threshold`), or a value it does not accept |
| `datadog_signal_group_by` | `signal.group_by` not a subset of the queries' `group_by` |
| `datadog_correlation` | A `signal_correlation` query without `rule` or with `query`; a `log_detection` query with `rule`; a `rule` that is neither a UUID nor a Datadog rule id |
| `datadog_condition` | A case condition that does not parse, names an unknown query, puts the number first (`3 < a`), or uses an operator the method does not allow (anomaly: `>`, `>=`, `&&`, `\|\|` only) |
| `datadog_severity` | A case severity outside the five Datadog statuses |
| `datadog_notification_alias` | A notification alias the tenant does not define (deploy time) |
| `datadog_tag` | A tag Datadog would refuse or rewrite: more than 200 characters, upper case, or a character outside `[a-z0-9_\-:./]` |

### 4.4 Signal correlation across Tide rules

A `signal_correlation` query names the rule whose signals it counts with `rule`:

- **A UUID is a Tide rule.** Deploy resolves it to the Datadog rule id that
  `.opentide/states/deployment/` holds for the same tenant, and deploys the referenced rule first.
  A reference to a rule that is not deployed to that tenant fails the correlation rule
  (`datadog_correlation_unresolved`), never the whole run.
- **Anything else is a Datadog rule id**, for rules opentide does not own, such as Datadog's own
  default rules.

The two never collide: a Tide UUID is 8-4-4-4-12 hex digits, a Datadog rule id three groups of
three (7.3).

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
        rule: def-000-xyz                              # a Datadog rule (illustrative id)
        correlate_by: ["@usr.email"]
    detection:
      window: 15m
    cases:
      - condition: bruteforce > 0 && mfa_reset > 0
        severity: critical
```

### 4.5 Other methods, for comparison

The method's settings sit beside it, so a reader sees all of a method in one place:

```yaml
    # A user logs in from a country they have not used in the last 30 days.
    queries:
      - query: source:okta @evt.name:user.session.start @evt.outcome:SUCCESS
        group_by: ["@usr.email"]
        new_value: ["@network.client.geoip.country.name"]
    detection:
      method: new_value
      learning: 7d
      forget_after: 30d
    cases:
      - severity: medium

    # Impossible travel, ignoring moves the user has made before.
    queries:
      - query: source:okta @evt.name:user.session.start @evt.outcome:SUCCESS
        group_by: ["@usr.email"]
    detection:
      method: impossible_travel
      learning: 7d
      ignore_known_transitions: true
    cases:
      - severity: high

    # Many distinct users fail to log in from one address.
    queries:
      - name: failures
        query: source:okta @evt.outcome:FAILURE
        group_by: ["@network.client.ip"]
        count_distinct: "@usr.email"
    detection:
      window: 10m
    cases:
      - condition: failures > 20
```

### 4.6 The condition grammar

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
| Precedence | None: `a OR b AND c` is `a +b +c` | `AND` (explicit or implied) binds tighter than `OR` (the precedence of VRL, Datadog's open-source implementation; **unverified** on Cloud SIEM itself, open question 2) |
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

Written from Datadog's Log Search Syntax page first, then checked against VRL's grammar (Datadog's
open-source parser for the same syntax) and against the queries Datadog itself publishes (5.5,
9.1). Where VRL and the docs differ, the docs win and the difference is a diagnostic or an open
question, never a silent choice.

```text
query       = or_expr?
or_expr     = and_expr ( OR and_expr )*
and_expr    = unary ( AND? unary )*                   // juxtaposition is AND
unary       = ( "-" | "+" | "NOT" ) unary | primary   // "-" and "+" written attached
primary     = "(" or_expr ")"
            | "*:*"                                   // every event
            | cidr_call
            | field ":" value
            | field ":" "(" value_expr ")"            // value group
            | value                                   // free text
cidr_call   = "CIDR" "(" attribute ( "," CIDR_BLOCK )+ ")"
field       = attribute | calculated | "*" | tag_key  // "*:term" searches every attribute
attribute   = "@" PATH
calculated  = "#" PATH
tag_key     = PATH                                    // reserved attributes and tags
value       = PHRASE | comparison | range | TERM | "*"
comparison  = ( ">=" | "<=" | ">" | "<" ) ( NUMBER | TERM )
range       = ( "[" | "{" ) BOUND "TO" BOUND ( "]" | "}" )
value_expr  = value_and ( OR value_and )*
value_and   = value_unary ( AND? value_unary )*
value_unary = ( "-" | "NOT" ) value_unary | "(" value_expr ")" | value
AND         = "AND"                                   // "&&" also, in VRL (datadog_symbol_operator)
OR          = "OR"                                    // "||" also, in VRL
```

Lexing rules:

- **Phrases.** Straight double quotes, `\X` escapes. Curly quotes are not quotes.
- **Terms.** A term may not start with `( ) [ ] { } " : - + ! ~ ^ ? * \ > = <` or whitespace, and
  may not contain an unescaped `: ! ~ ^ < >` anywhere (VRL's `TERM_CHAR`). Inside a term, `-`,
  `+` and `=` are ordinary. `*` and `?` are wildcards, `**` matches across words, and `\ ` joins
  two words.
- **Escapes.** A backslash escapes any one character. The set Datadog says to escape is
  ``- ! && || > >= < <= ( ) { } [ ] " * ? : \ #`` and space; `/` is not special. A value starting
  with `-` must escape it (`@x:\-1`), since `-` there would be read as exclusion; a comparison may
  take a negative number (`@x:>-1`).
- **Numbers** follow VRL's `-?\d+(\.\d+)?(E-?\d+(\.\d+)?)?`.
- **Operators.** `AND`, `OR`, `NOT` and `TO` are operators only in upper case. `NOT(` needs no
  space.
- **Range bounds** are any run without whitespace or a closing bracket, `*` for an open end.
- **Fields.** A field is everything before the first unescaped `:` of a term.
  - `@` starts an attribute path, `#` a calculated field, and a bare name is a tag or one of the
    reserved attributes (`host`, `source`, `status`, `service`, `trace_id`, `message`).
  - A tag that is not `key:value` is searched as `tags:<tag>`.
  - Dots separate path segments. A dot or space inside a key is escaped.

Not part of the language, so refused or flagged:

- **Regex, fuzzy and boost** (`/re/`, `~`, `^`). Datadog has none; `/` is an ordinary character.
- **Lower-case operators.** They are terms.
- **`_exists_:` and `_missing_:`.** These are documented only for Observability Pipelines; the
  `search` profile accepts them with a warning, and the `rule` profile does not.

### 5.4 Diagnostics (first draft)

| Code | Severity | Fires on |
|---|---|---|
| `datadog_parse_error` | error | Unbalanced parentheses or brackets, a dangling operator, an empty group, `field:` without a value, a comma outside `CIDR(…)` |
| `datadog_lowercase_operator` | warning | `and`, `or`, `not` or `to` between clauses: they are search terms |
| `datadog_curly_quote` | warning | `“…”`: Datadog ignores curly quotes, so the phrase becomes separate terms |
| `datadog_wildcard_in_phrase` | warning | `"*test*"`: wildcards inside quotes are punctuation in Log Explorer |
| `datadog_unescaped_special` | error | An unescaped `: ! < >` inside a term (`@a:b:c`, `foo!bar`), or a value that starts with an unescaped `-` (`@x:-1`) |
| `datadog_symbol_operator` | warning | `&&` or `\|\|` between clauses: VRL reads them as `AND` and `OR`, but Datadog's docs list them only among the characters to escape |
| `datadog_detached_operator` | warning | `- term` with a space: VRL still applies it, but the docs never write it so |
| `datadog_cidr` | error | `CIDR` with no attribute, a tag instead of an `@attribute`, or a block that is not an IPv4 or IPv6 CIDR |
| `datadog_range` | error / warning | A lower-case `to` or a malformed range (error); mixed bounds `[a TO b}` (warning: VRL accepts them, the docs never show them) |
| `datadog_mixed_boolean` | warning | `a OR b c`, where the implied AND binds tighter than the OR beside it; suggest parentheses |
| `datadog_full_text_in_rule` | warning | `*:term` in profile `rule` |
| `datadog_pipelines_only` | warning | `_exists_:` or `_missing_:` (Observability Pipelines syntax) |
| `datadog_regex` | error | `~` or `^` in a term: Datadog has no fuzzy or boost operators, and no regex (`/` is an ordinary character, so `@http.url:/api` is a path, not a regex) |
| `datadog_unknown_attribute` | hint | A dotted bare key (`evt.name:x`), searched as a tag where an attribute was likely meant; with catalogs, an `@attribute` that neither the standard attributes nor the source's pipeline catalog knows (5.7) |

### 5.6 Highlighting (existing captures only)

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

### 5.7 Catalogs

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
| `type` | `type` |
| `queries[]` | `queries[]`: `query`, `name`, `from` → `dataSource`, `group_by` → `groupByFields`, `keep_missing_groups` → `hasOptionalGroupByFields`. The measure becomes `aggregation` with its field: none → `count`; `count_distinct` → `cardinality` + `distinctFields`; `sum`/`max` → `metrics: [field]`; `new_value` → `metrics`. Impossible travel → `geo_data` + `metrics: ["@network.client.geoip"]`; correlation → `event_count`, `rule` resolved to `ruleId` (4.4), `correlate_by` → `correlatedByFields` |
| `detection` | `options.detectionMethod`, `options.evaluationWindow`, and the method's settings into `newValueOptions`, `anomalyDetectionOptions` or `impossibleTravelOptions`, each in the unit that field takes |
| `cases[]` | `cases[]`. `severity` (or `response.alert_severity` mapped Informational→`info`, Low→`low`, Medium→`medium`, High→`high`, Critical→`critical`) becomes `status`; `notify` aliases are resolved into `notifications` |
| `signal` | `groupSignalsBy`, `options.keepAlive`, `options.maxSignalDuration`, `options.decreaseCriticalityBasedOnEnv`, `hasExtendedTitle` |
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
| [DataDog/integrations-core](https://github.com/DataDog/integrations-core) and [integrations-extras](https://github.com/DataDog/integrations-extras): log saved views (135, 169 unique queries), `logs("…")` monitors (31), pipeline test fixtures (`assets/logs/`, 408 files) | BSD-3-Clause | Real Datadog search queries written by Datadog, sources and attribute remaps, sample logs | **(a) Conformance corpus**, vendored with the notice. Catalogs (5.7). Sample events for `POST /rules/test` |
| integrations-extras `*/assets/security/*.json` (AppOmni, Bottomline, Contrast: 11 rules) | BSD-3-Clause | The only permissively licensed rules already in Datadog's export format: threshold, impossible travel, anomaly and third party | **API body fixtures** and **(b) seed rules** |
| [terraform-provider-datadog](https://github.com/DataDog/terraform-provider-datadog) test cassettes `TestAccDatadogSecurityMonitoringDefaultRule_*.yaml` | MPL-2.0 files, recording Datadog's proprietary rule content | 199 recorded built-in rules: 82 `log_detection` with 122 unique queries (67 CloudTrail, Microsoft 365, 1Password, Kubernetes audit), real escaping (`system\:serviceaccount\:*`), every detection method | **Measured, not vendored**, as Exabeam's content hub: an ignored test reads a local checkout. The provider's `examples/` and the [datadog-api-client-*](https://github.com/DataDog/datadog-api-client-python) `examples/v2/security-monitoring` (Apache-2.0) give API fixtures |
| [DataDog/documentation](https://github.com/DataDog/documentation) `hugo/content/en/api/v2/security-monitoring/request.*Rule*.json` | to confirm (GitHub reports NOASSERTION) | 42 synthetic API request bodies covering every rule type and detection method | Schema fixtures once the licence is confirmed; until then, a reference only |
| [vectordotdev/vrl](https://github.com/vectordotdev/vrl) `src/datadog/search/` | MPL-2.0 | Datadog's own pest grammar for the search syntax, with its tests | The grammar reference and a **differential oracle** (`scripts/engine/oracles/datadog/`): run VRL over the corpus and compare accept and reject verdicts. Not vendored |
| [DataDog/stratus-red-team](https://github.com/DataDog/stratus-red-team) (103 techniques, 36 detonation logs), [grimoire](https://github.com/DataDog/grimoire), [threatest](https://github.com/DataDog/threatest) | Apache-2.0 | Attack, recorded logs, and an assertion that the Datadog signal fired | Seed rules written against Stratus techniques, with the detonation logs as their `POST /rules/test` samples; a manual tenant run like `microsoft-defender-tenant-test.md` |
| [DataDog/security-agent-policies](https://github.com/DataDog/security-agent-policies) | Apache-2.0 | 331 Workload Protection rules in SECL | Out of scope (a different language) |
| Community Terraform (139 files contain `resource "datadog_security_monitoring_rule"`, nearly all docs, forks or tooling; for example grcengineering/how-to-harden, MIT, 7 rules on `source:audit`) | mixed; several have no licence | Tiny sets | Only MIT or Apache-2.0 ones, as examples; never an unlicensed repository |
| panther-analysis (Apache-2.0), splunk/security_content (Apache-2.0), Azure-Sentinel (MIT), elastic/detection-rules (Elastic License 2.0) | as listed | Rules in other languages | Ideas for coverage, not content; nothing from ELv2 |

### 9.1 What the prototype checker already shows

The tokenizer prototype in the technical artifact implements sections 4.6 and 5.3 to 5.6. It was run over
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
