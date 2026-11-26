---
title: "RFC: Datadog Cloud SIEM platform"
description: "Proposal for a fourteenth platform, datadog: Datadog Cloud SIEM detection rules as a Tide block, the Datadog search syntax as a new engine language held to Datadog's own published queries, deploy and live validation through the v2 Security Monitoring API, and the content to start from."
---

# RFC: Datadog Cloud SIEM platform

| | |
|---|---|
| **Status** | Proposed |
| **Date** | 2026-11-26 |
| **Platform** | `datadog`, Datadog Cloud SIEM, model `platform::datadog::1.0` |
| **Language** | `datadog`, the Datadog search syntax, crate `opentide-datadog` |
| **Specs it calls for** | opentidehq/specifications `specs/platforms/datadog-1.0.md` (sections 5 and 8 are its draft) and `specs/languages/datadog-1.0.md` (section 6) |
| **Related** | The language-versus-dialect review (a proposed ADR, 0015) states the general rule that section 6.2 applies to Datadog |

RFCs normally live in opentidehq/specifications `rfcs/`. This one is written here, beside the code
it plans, and moves there with a number when the specifications are drafted (phase 0).

Research was done on 2026-11-26 against these sources:

- Datadog's online documentation;
- its public OpenAPI v2 specification;
- the Terraform provider's code and tests;
- 3,229 log-search queries that Datadog itself publishes.

A fact the public sources did not settle is marked **(unverified)**. Each is listed with the
probe that settles it in [Open questions](#16-open-questions).

## 1. Summary

Add **`datadog`, Datadog Cloud SIEM**, as the fourteenth built-in platform.

- **The block.** A `configurations.datadog` block describes one real-time Cloud SIEM detection
  rule. 1.0 covers the threshold, new value, anomaly and impossible travel methods. Its keys are
  grouped by meaning rather than by the API's layout:
  - `queries`: what to look at;
  - `detection`: how the queries become a match;
  - `cases`: when a match becomes a signal;
  - `signal`: what happens to the signal.

  Correlation across rules waits for 1.x and Datadog's sequence rules. Datadog no longer accepts
  new `signal_correlation` rules (4).
- **The language.** The Datadog search syntax becomes an engine language, id `datadog`. It is
  implemented in a new pure-Rust crate, `opentide-datadog`, and not as a fourth Lucene dialect: its
  operator precedence differs, and the difference reaches the parse tree. The case conditions
  (`failed > 10 && success > 0`) get a small parser in the platform model, as Graylog's conditions
  do.
- **The connector.**
  - Deploy goes through `/api/v2/security_monitoring/rules`.
  - `validate query --live` calls Datadog's own `POST /rules/validation`.
  - `opentide query` runs searches through the Logs Search API.
- **The evidence.** The grammar is written from Datadog's docs and checked against two references
  (section 11):
  - the 3,229 log-search queries Datadog publishes;
  - the grammar in VRL, the open-source library behind Datadog's Observability Pipelines.

  A token-level prototype of the checks already finds three real mistakes in Datadog's own
  content. No converted third-party content is used.

| `--platform` | Product | Deploy | Compiled without a tenant | Tenant check (`--live`) | Offline engine | `opentide query` |
|---|---|:-:|:-:|:-:|---|---|
| `datadog` | Datadog Cloud SIEM | ✅ | ✅ | ✅ (`POST /rules/validation`) | Datadog search syntax (`.datadog`) | Datadog search syntax (Logs Search API) |

## 2. Motivation

Datadog Cloud SIEM is a common SIEM for teams that already send their logs to Datadog.

- **Its rules are JSON documents behind a REST API.**
- **Datadog recommends detection as code.** It promotes Terraform
  (`datadog_security_monitoring_rule`) and its own validate, test, backtest and convert endpoints
  ("Detection as code for Cloud SIEM", 2025-06-11).
- **No portable format exists.** There is no vendor-neutral way to write those rules beside the
  same detection for Sentinel, Splunk or Elastic, which is what opentide exists to provide.

The language is not well served either:

- **There is no reference grammar.** Datadog documents the search syntax in prose and publishes no
  grammar for the syntax its products use. The nearest is VRL's grammar for Observability
  Pipelines, a related dialect: it has no `CIDR()` and no `*:term`, and it accepts the pipelines'
  own `_exists_:` (section 6.6).
- **Silent traps change what a rule matches without an error.**
  - A lower-case `and` becomes a search term.
  - Curly quotes are ignored.
  - `*` inside quotes is not a wildcard.
  - `a OR b c` means `a OR (b AND c)`.

  Section 11.3 shows these in Datadog's own published queries.

## 3. Terminology

| Term | Meaning |
|---|---|
| **Detection rule** | A Datadog object (`/api/v2/security_monitoring/rules/{id}`) that runs queries over incoming events and creates signals. One `configurations.datadog` block is one detection rule |
| **Default rule** | A rule Datadog ships and maintains (`isDefault: true`). It can be enabled, re-tagged and given notifications, but not deleted or rewritten. opentide never changes one |
| **Query** | One search over a data source (`queries[]`), with a name that conditions refer to |
| **Search syntax** | The language of a query's `query` string: Datadog's log search syntax, which the API calls `event_query`. Language id `datadog` |
| **Detection method** | How queries become a match. `threshold` compares counts with a condition. `new_value` fires on a value not seen while learning. `anomaly` fires on a count above a learned baseline. `impossible_travel` fires on two logins too far apart for the time between them |
| **Evaluation window** | The sliding period the cases are tested over (`detection.window`) |
| **Case** | A condition over the queries, with a severity and notification targets. Cases are tested in order, and the first that matches creates or updates the signal |
| **Condition** | A case's expression over query names: `failed > 10 && success > 0` |
| **Signal** | What a rule creates when a case matches: Datadog's alert object, shown in the Signals Explorer |
| **Keep alive** | How long a signal stays open while matches keep arriving. With no match for that long, it closes |
| **Maximum signal duration** | How long after its first match a signal closes, whatever still matches |
| **Notification rule** | A Datadog setting outside any detection rule that routes signals to people by severity, tags or rule. It applies whatever a rule's own `notifications` say |
| **Site** | The Datadog region of an organisation (`datadoghq.com`, `datadoghq.eu`, …), whose API is `https://api.<site>` |
| **Dialect, profile** | As the language review defines them. A dialect is one grammar whose diagnostics differ by product, as Lucene's do for Elastic, Carbon Black and Graylog. A profile is one language with fewer constructs allowed in one context; this RFC's profiles are `rule` and `search` |

## 4. Scope

| In `datadog-1.0` | Later (`datadog-1.x`) | Out of scope |
|---|---|---|
| Real-time `log_detection` rules | **Cross-rule correlation**, on `sequence` rules (steps and transitions) with queries over signals. Its design (5.6) needs deploy ordering, cycle and delete rules, and a dry-run placeholder | `signal_correlation`: Datadog refuses new ones (403, per the Terraform provider's tests as of the checkout of 2026-11-25), and its create docs no longer list it |
| Methods `threshold`, `new_value`, `anomaly`, `impossible_travel` | Content anomaly (its API value is unverified; the enum has `anomaly_threshold`), `third_party`; scheduled rules (`schedulingOptions`, an RFC 5545 RRULE) and their `calculatedFields` | `workload_security`, `workload_activity`: Agent rules written in SECL, another language |
| Queries `from` `logs` (the default), `audit`, `events`, `signals` | Reference tables (`referenceTables`); `spans`, `network`, `security_runtime` | `application_security`, `api_security`, `cloud_configuration`, `infrastructure_configuration` |
| Live validation, deploy, disable, delete, drift | Tuning a default rule (`customQueryExtension`, `customStatus`, notifications), like Sysdig's `append_to_rule` | `queryLanguage: sql` (DDSQL): SQL stays unsupported in opentide |
| `opentide query` over the Logs Search API | Rule tests (`POST /rules/test`); backtests (historical jobs, in preview); an importer (12) | `hardcoded` (one Datadog-owned value, `log4shell`) |
| | The new value and anomaly baselines (`instantaneousBaseline`, `learningPeriodBaseline`) | Suppression rules and security filters as Tide objects (open question 8) |

## 5. The Tide block: `platform::datadog::1.0`

### 5.1 Minimal block

The smallest block that deploys is a threshold rule with one query and one case:

```yaml
configurations:
  datadog:
    schema: platform::datadog::1.0
    status: PRODUCTION
    queries:
      - query: source:cloudtrail @evt.name:ConsoleLogin @evt.outcome:Failure
    cases:
      - condition: a > 5
```

Defaults fill the rest:

- the method is `threshold` and the window `5m`;
- the query is named `a` and counts events;
- the severity comes from `response.alert_severity`;
- the signal stays open `1h` without new matches, and at most `1d`.

### 5.2 Complete block

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
    status: PRODUCTION
    queries:
      - name: failed
        query: |
          source:okta @evt.name:user.session.start @evt.outcome:FAILURE
        from: logs
        group_by: ["@usr.email"]
      - name: success
        query: |
          source:okta @evt.name:user.session.start @evt.outcome:SUCCESS
        group_by: ["@usr.email"]
    detection:
      method: threshold
      window: 5m                     # the cases are tested over the last 5 minutes
    cases:
      - name: brute force then success
        condition: failed > 10 && success > 0
        severity: high               # default: response.alert_severity
        notify: [soc]                # tenant aliases or raw @handles
    signal:
      group_by: ["@usr.email"]       # one signal per user
      keep_alive: 1h                 # open while matches keep arriving within an hour
      max_duration: 1d               # closed a day after the first match regardless
      downgrade_non_production: true # one level lower when env starts with staging, test or dev
      group_in_notification_title: true
    message: |
      {{@usr.email}} failed to log in {{events_matched_per_query.failed}} times, then succeeded.
    tags: ["team:identity"]
```

### 5.3 Why the block is grouped this way

The API puts these side by side in one `options` object:

- `evaluationWindow`, `keepAlive` and `maxSignalDuration`;
- `decreaseCriticalityBasedOnEnv`;
- `newValueOptions`, `anomalyDetectionOptions` and `impossibleTravelOptions`.

It puts `groupSignalsBy` and `hasExtendedTitle` at the top level. These answer different
questions, so the block separates them:

- **The evaluation window is part of detecting.** Datadog's docs call it "a sliding period in which
  at least one case evaluates as true". It sits in `detection`, beside the method and the method's
  own settings.
- **The rest is about the signal once it exists.** Keep alive and maximum duration decide when a
  signal "remains open" and when it "closes". Signal grouping decides which matches merge into one
  signal. The non-production downgrade and the title decide how the signal reads. All of this
  sits in `signal`.
- **The measure belongs to its query.** The API spreads it over an `aggregation` enum,
  `distinctFields` and `metrics`, whose valid combinations depend on each other. The block uses
  one key that names both the measure and its field (`count_distinct: "@usr.email"`). With no
  measure key, a query counts events.

Datadog's own rule editor makes the same split, between its "detection method", "set rule cases"
and "other parameters" steps.

### 5.4 Keys

A key marked ✅ in the *Required* column must be present. Every other key may be left out and
takes its default.

#### Block

| Key | Type and allowed values | Required | Default | API property | Meaning |
|---|---|:-:|---|---|---|
| `schema` | `platform::datadog::1.0` | ✅ | | | |
| `status` | a status of the merged `deployment.toml` | ✅ | | | Selects the deploy strategy (8.3) |
| `enabled`, `name`, `flags`, `tenants`, `contributors` | as every block | | | | |
| `queries` | list of 1 to 10 queries **(the upper bound is unverified, open question 5)** | ✅ | | `queries` | |
| `detection` | map | | `{method: threshold, window: 5m}` | `options` | |
| `cases` | list of at least one case | ✅ | | `cases` | |
| `signal` | map | | see below | `options`, `groupSignalsBy`, `hasExtendedTitle` | |
| `message` | Markdown with Datadog template variables | | derived (7.3) | `message` | |
| `tags` | list of Datadog tags | | `[]` | `tags` | Added to the derived tags (7.4) |

`type` is always `log_detection` in 1.0 and is not written.

#### `queries[]`

| Key | Type and allowed values | Required | Default | API property | Meaning |
|---|---|:-:|---|---|---|
| `name` | `[a-z][a-z0-9_]*`, unique in the block | | `a`, `b`, … by position | `name` | What conditions call the query. Datadog's own detection tests name queries `first`, `second` and `my_query` (`first > 3 \|\| second > 10`, `my_query > 0.95`, terraform-provider-datadog `resource_datadog_security_monitoring_rule_test.go`). Not allowed on a `new_value` query (Terraform: "not compatible") |
| `query` | Datadog search syntax, profile `rule` | ✅ | | `query` | |
| `from` | `logs` \| `audit` \| `events` \| `signals` | | `logs` | `dataSource` (`signals` is `security_signals`) | The data the query searches |
| `group_by` | list of field paths | | `[]` | `groupByFields` | Matches are counted per distinct combination of these values |
| `keep_missing_groups` | bool | | `false` | `hasOptionalGroupByFields` | Keep an event that lacks a `group_by` value, grouped as `N/A`, instead of dropping it |
| `count_distinct` | one field path | | | `aggregation: cardinality`, `distinctFields` | The case compares the number of distinct values instead of events |
| `sum` | one numeric field path | | | `aggregation: sum`, `metrics` | The case compares the field's sum |
| `max` | one numeric field path | | | `aggregation: max`, `metrics` | The case compares the field's maximum |
| `new_value` | 1 to 5 field paths | with `method: new_value` | | `aggregation: new_value`, `metrics` | The fields whose unseen values trigger |

A query sets at most one of `count_distinct`, `sum`, `max` and `new_value`. Impossible travel's
aggregation, `geo_data` on `@network.client.geoip`, follows from the method and is never written.

#### `detection`

| Key | Type and allowed values | Required | Default | API property | Meaning |
|---|---|:-:|---|---|---|
| `method` | `threshold` \| `new_value` \| `anomaly` \| `impossible_travel` | | `threshold` | `options.detectionMethod` (`anomaly` is `anomaly_detection`) | |
| `window` | `0`, `1m`, `5m`, `10m`, `15m`, `30m`, `1h`, `2h`, `3h`, `6h`, `12h` or `1d` | | `5m` | `options.evaluationWindow` (seconds) | The sliding window the cases are tested over |
| `learning` | depends on the method (table below) | | per method | per method | How Datadog learns what is normal before it creates signals |
| `forget_after` | `1d` to `30d`, whole days | with `new_value` | | `newValueOptions.forgetAfter` (days) | A learned value unseen for this long is new again. Required, with no default, as Terraform has it |
| `bucket` | `5m`, `10m`, `15m`, `30m`, `1h` or `3h` | | `5m` **(unverified default)** | `anomalyDetectionOptions.bucketDuration` (seconds) | The time bucket the baseline is computed on |
| `tolerance` | integer, 1 to 5 | | `3` **(unverified default)** | `anomalyDetectionOptions.detectionTolerance` | How far above the baseline counts as anomalous |
| `detect_ip_transitions` | bool | | `false` | `impossibleTravelOptions.detectIpTransition`, sent only when `true` | The spec: "the rule detects transitions between IP addresses of the same user". Its exact effect is **unverified** (open question 6) |

`learning` is one key for one idea across three methods; the compiler converts it to what each API
property takes:

| Method | `learning` | Default | API properties |
|---|---|---|---|
| `new_value` | `0d` to `30d` in whole days: learn for that long. The spec says `0d` means "a signal will be generated for all new values after the first value is learned" | `1d` | `learningMethod: duration`, `learningDuration` (days). The editor's two other options, "for all new values" and "after the first seen value" (`learningMethod: threshold`, `learningThreshold` 0 or 1), wait for phase 0 to map them (open question 6) |
| `anomaly` | `1h`, `6h`, `12h`, `1d`, `2d`, `7d` or `14d` | `7d` **(unverified default)** | `anomalyDetectionOptions.learningDuration` (hours) |
| `impossible_travel` | `1d` to `30d` in whole days; setting it sets `baselineUserLocations: true` | unset: no location baseline | `impossibleTravelOptions.baselineUserLocationsDuration` (days) |

A key the method does not take, such as `bucket` with `threshold`, is refused
(`datadog_detection_option`).

An impossible travel block may set neither `learning` nor `detect_ip_transitions`. The spec says
that at least one of `baselineUserLocations` and `detectIpTransition` must be true, but Datadog's
own client example creates a rule with `baselineUserLocations: false` and no `detectIpTransition`,
and its docs call the disabled baseline the default. The block follows the example, and the
spec's sentence is open question 6.

#### `cases[]`

| Key | Type and allowed values | Required | Default | API property | Meaning |
|---|---|:-:|---|---|---|
| `name` | text | | `""` | `name` | |
| `condition` | the condition grammar (5.8) | with `threshold` and `anomaly` | | `condition` | With `anomaly`, the number is a percentile between 0 and 1: `a > 0.995` fires when the count beats 99.5% of past periods |
| `severity` | `info` \| `low` \| `medium` \| `high` \| `critical` | | from `response.alert_severity`, else `info` | `status` | |
| `notify` | list of tenant aliases or `@handles` | | `[]` | `notifications` | Left out in a `PREVIEW` deploy (8.3) |

#### `signal`

| Key | Type and allowed values | Required | Default | API property | Meaning |
|---|---|:-:|---|---|---|
| `group_by` | list of field paths, each in some query's `group_by` **(the exact subset rule is unverified)** | | unset: no signal grouping, as Datadog's "Group signals" toggle | `groupSignalsBy` | Matches with the same values update one signal |
| `keep_alive` | a `detection.window` value, at least `detection.window` | | `1h` | `options.keepAlive` (seconds) | The signal stays open while a case matches again within this time |
| `max_duration` | a `detection.window` value, at least `detection.window` | | `1d` | `options.maxSignalDuration` (seconds) | The signal closes this long after its first match, whatever still matches |
| `downgrade_non_production` | bool | | `false` | `options.decreaseCriticalityBasedOnEnv` | One severity level lower when the `env` tag starts with `staging`, `test` or `dev` |
| `group_in_notification_title` | bool | | `false` | `hasExtendedTitle` | Notifications put the group-by values in their title |

### 5.5 Names

The names were chosen for the person reading a rule, and do not copy the API:

| API | Block | Why |
|---|---|---|
| `options.detectionMethod` | `detection.method` | |
| `options.evaluationWindow` | `detection.window` | The only window in `detection`, so it needs no qualifier |
| `options.keepAlive` | `signal.keep_alive` | Datadog's own term, which its users know; `signal.` says what is kept alive |
| `options.maxSignalDuration` | `signal.max_duration` | `signal.` already says whose duration |
| `options.decreaseCriticalityBasedOnEnv` | `signal.downgrade_non_production` | Says what happens, and to which signals; "criticality" is not a word the rest of Tide uses |
| `groupSignalsBy` | `signal.group_by` | The same word as `queries[].group_by`, in the scope it applies to |
| `hasExtendedTitle` | `signal.group_in_notification_title` | Says what the notification's title gains |
| `hasOptionalGroupByFields` | `queries[].keep_missing_groups` | Says what the switch keeps |
| `aggregation`, `distinctFields`, `metrics` | `count_distinct`, `sum`, `max`, `new_value` | One key names the measure and its field |
| `newValueOptions`, `anomalyDetectionOptions`, `impossibleTravelOptions` | `detection.learning`, `forget_after`, `bucket`, `tolerance`, `detect_ip_transitions` | Beside the method they belong to |
| `dataSource` | `from` | Reads as the query's source: `from: audit` |
| `notifications`, a case's `status` | `notify`, `severity` | `status` already means a Tide status |

### 5.6 Correlation, in 1.0 and in 1.x

Datadog no longer accepts new `signal_correlation` rules: the Terraform provider's test skips them
because the "API no longer allows creating signal_correlation rules (403)" (2026-11-25), and the
create docs list Sequence instead.

**In 1.0,** a rule can still count other rules' signals with a query `from: signals`, searched
with the same syntax. Which signal attribute names the rule that raised a signal is
**unverified** (open question 9), so 1.0 offers no shortcut for it.

**In 1.x,** cross-rule correlation comes with `sequence` rules. A step may name a Tide rule by UUID,
and deploy resolves it to the Datadog id in the deployment state. That needs design this RFC does
not settle:

- the order in which deploy creates referenced rules;
- cycles;
- the reverse order on deletion;
- a run whose change set lacks the referenced rule;
- what `--dry-run` and the offline compiler show for an id they cannot know;
- telling a UUID from a Datadog rule id, whose format is unverified (8.5).

### 5.7 The other methods

Each method's settings sit beside it, so a reader sees all of a method in one place:

```yaml
    # New value: a user logs in from a country not seen for them in the last 30 days.
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

    # Impossible travel, with a learned location baseline per user.
    queries:
      - query: source:okta @evt.name:user.session.start @evt.outcome:SUCCESS
        group_by: ["@usr.email"]
    detection:
      method: impossible_travel
      learning: 7d
    cases:
      - severity: high

    # Anomaly: more denied API calls than 99.5% of this role's past periods.
    queries:
      - name: denied
        query: source:cloudtrail @error.kind:AccessDenied
        group_by: ["@userIdentity.arn"]
    detection:
      method: anomaly
      window: 15m
      bucket: 15m
      learning: 7d
    cases:
      - condition: denied > 0.995

    # A threshold on distinct values: many users fail to log in from one address.
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

### 5.8 The condition grammar

```text
condition  = or_expr
or_expr    = and_expr ( "||" and_expr )*
and_expr   = comparison ( "&&" comparison )*
comparison = query_name ( ">" | ">=" | "<" | "<=" ) number
query_name = [a-z][a-z0-9_]*
number     = [0-9]+ ( "." [0-9]+ )?
```

- **The query name comes first.** Datadog's docs say "`a > 3` is allowed; `3 < a` is not".
- **`<` and `<=` are documented for threshold rules only.**
- **Under `anomaly`, the number is a percentile in (0, 1).** Datadog's examples use `a > 0.995`.
  A number outside that range is refused.
- **Precedence is undocumented.** Datadog documents both `&&` and `||` ("logical operations
  (`>`, `>=`, `&&`, `||`)"), but not which binds tighter, nor whether parentheses are accepted.
  Mixing them is a warning, as Exabeam's `exabeam_mixed_boolean` is, until a tenant settles it.

### 5.9 Block constraint codes

Each is its own finding at its own field path, as `graylog_constraints` reports them.

| Code | Severity | Finding | Example |
|---|---|---|---|
| `datadog_method_unsupported` | error | `detection.method` outside the 1.0 scope | `method: sequence` |
| `datadog_duration` | error | A duration outside the values its key accepts | `window: 7m`; `learning: 3h` with `new_value` |
| `datadog_window_order` | error | `detection.window` longer than `signal.keep_alive` or `signal.max_duration` | `window: 1h` with `keep_alive: 30m` |
| `datadog_query_name` | error | Not `[a-z][a-z0-9_]*`, a duplicate, or a name on a `new_value` query | `name: Failed-Logins` |
| `datadog_measure` | error | More than one measure; `new_value` without `method: new_value`, or the reverse; more than five `new_value` fields | `count_distinct` and `sum` on one query |
| `datadog_detection_option` | error | A `detection` key the method does not take; `new_value` without `forget_after` | `bucket: 5m` with `method: threshold` |
| `datadog_signal_group_by` | error | A `signal.group_by` field that no query groups by | `signal.group_by: ["@usr.id"]` when the queries group by `@usr.email` |
| `datadog_condition` | error | A condition that does not parse, names an unknown query, puts the number first, uses an operator the method does not allow, or an `anomaly` number outside (0, 1) | `3 < failed`; `fail > 1` with no query `fail`; `a > 5` with `anomaly` |
| `datadog_condition_mixed` | warning | `&&` and `\|\|` in one condition, whose precedence is undocumented | `a > 1 \|\| b > 1 && c > 1` |
| `datadog_severity` | error | A case severity outside the five Datadog statuses | `severity: urgent` |
| `datadog_notification_alias` | error, at deploy | A notification alias the tenant does not define | `notify: [secops]` with no `secops` alias |
| `datadog_tag` | error | A tag Datadog would refuse or rewrite: longer than 200 characters, not starting with a letter, upper case, or a character outside `[a-z0-9_\-:./]` | `tags: ["Team:Identity"]` |

## 6. The language: Datadog search syntax (`datadog`)

### 6.1 Identity

| Item | Value |
|---|---|
| Language id | `datadog` (`LanguageId::Datadog`); open question 1 weighs `ddsearch` |
| Crate | `opentide-datadog`, foundation tier 2, beside `opentide-cql` |
| File suffix | `.datadog` |
| Diagnostic code prefix | `datadog_` |
| Comments | None: the language has no comment syntax |
| Profile `rule` | A block's `queries[].query`. Full-text `*:term` is a warning: Datadog's docs allow it in Log Management's "monitor, dashboard, and notebook queries", a list detection rules are not on. A calculated field (`#name`) is a warning: real-time rules have none |
| Profile `search` | `.datadog` files, hunts with `system: datadog`, and `opentide query`. `*:term` and `#name` are allowed |

### 6.2 A new crate, not a Lucene dialect

`opentide-lucene` already serves three dialects: Elastic, Carbon Black and Graylog. The Datadog
syntax looks like Lucene, but it differs in ways that reach the tree, not only the diagnostics:

| | Lucene classic (`opentide-lucene`) | Datadog search syntax |
|---|---|---|
| Precedence | None: `a OR b AND c` is `a +b +c` | AND, written or implied, binds tighter than OR, as VRL's grammar has it (**unverified** on Cloud SIEM, open question 2) |
| Fields | `field:value` | `@attribute.path:value` for attributes; bare `key:value` for tags and reserved attributes; `#name` for calculated fields |
| Functions | none | `CIDR(@attr, block, …)` |
| Wildcards | `*`, `?` | `*` within a word, `**` across words, `\ ` to join words, `?` for one character; none inside quotes |
| Regex, fuzzy, boost | `/re/`, `~`, `^` | none; `/` is an ordinary character |
| Free text | the default field | `message`, `@title`, `@error.message` and `@error.stack` only; `*:term` searches every attribute |
| Values | analyser dependent | Numbers may carry duration units (`@duration:>=100ms`) |

A dialect flag would make the single walk branch on the dialect at almost every node, and the
precedence changes the tree's shape. That is the line the language review draws between a
language and a dialect.

The crate follows the [add-language skill](../../.agents/skills/add-language/SKILL.md) unchanged:

- a logos lexer and a hand-written Pratt grammar on `opentide-parse`;
- a lossless rowan tree, with `src/datadog.ungram`;
- the depth contract;
- one walk for the checks and the highlight.

### 6.3 Grammar

The grammar is written from Datadog's Log Search Syntax page, then checked against VRL's grammar and
against Datadog's published queries (6.6, 11). Where VRL and the docs differ, the docs win, and the
difference becomes a diagnostic or an open question, never a silent choice.

```text
query       = or_expr?
or_expr     = and_expr ( OR and_expr )*
and_expr    = unary ( AND? unary )*                   // juxtaposition is AND
unary       = ( "-" | "+" | "NOT" )? primary          // one modifier; "-" and "+" attached
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
value_unary = ( "-" | "NOT" )? ( "(" value_expr ")" | value )
AND         = "AND"                                   // VRL also reads "&&" (datadog_symbol_operator)
OR          = "OR"                                    // VRL also reads "||"
```

Whitespace may separate a field's `:` from its value (`env: prod`). VRL allows this, and
Datadog's pipelines and docs write it 15 times. Modifiers do not stack: `--a` is refused, as in
VRL, and so are `NOT NOT a` and `-NOT a`, which VRL accepts.

### 6.4 Lexical rules

- **Phrases.** They are in straight double quotes and take `\X` escapes. Curly quotes are not
  quotes.
- **Terms.**
  - A term starts with an escape, a `*` or `?` wildcard, or any character except whitespace and
    ``( ) [ ] { } " : - + ! ~ ^ \ > = <``.
  - A term may not contain an unescaped `! ~ ^ < >` anywhere, after VRL's `TERM_CHAR`, nor an
    unescaped `:` after its field (6.7).
  - Inside a term, `-`, `+`, `=`, `/`, `$` and `,` are ordinary characters.
- **Wildcards.** `*` and `?` are wildcards in a term. `**` matches across words, and `\ ` joins two
  words.
- **Escapes.** A backslash escapes any one character. Datadog's list of characters to escape is
  ``- ! && || > >= < <= ( ) { } [ ] " * ? : \ #`` and space; `/` is not special.
  - A value that starts with `-` must escape it (`@x:\-1`), since `-` there means exclusion.
  - A comparison may take a negative number (`@x:>-1`).
- **Numbers** follow VRL's `(-|\-)?\d+(\.\d+)?(E(-|\-)?\d+(\.\d+)?)?`. A number may be followed by a
  duration unit: `ns`, `us`, `µs`, `ms`, `s`, `m`, `min`, `h`, `d`, `day`, `days` or `w`.
- **Operators.** `AND`, `OR`, `NOT` and `TO` are operators only in upper case. `NOT(` needs no
  space.
- **Range bounds** are any run without whitespace or a closing bracket, with `*` for an open end.
- **Commas** separate the arguments of `CIDR(…)`, and are ordinary characters everywhere else.
- **Fields.** A field is everything before the first unescaped `:` of a term.
  - `@` starts an attribute path, and `#` a calculated field.
  - A bare name is a tag or a reserved attribute: `host`, `source`, `status`, `service`, `trace_id`
    or `message`.
  - Dots separate path segments. A dot or space inside a key is escaped (`@user.first\ name`).

### 6.5 Semantics the checker relies on

- **Precedence.** `-`/`NOT` bind tightest, then AND (written or implied), then OR, the same inside
  a value group. This is **unverified** on Cloud SIEM. The model follows VRL, and every diagnostic
  that depends on it says so.
- **Value groups.** In `field:(a b)`, juxtaposition is AND: Datadog's example `@user_perms:(4 6)`
  matches an array holding both. Comparisons and ranges apply to the group's field
  (`@http.status_code:(>=400 <500)`).
- **Case.**
  - Operators are case-sensitive.
  - Attribute values are case-sensitive.
  - Free-text search is not case-sensitive.
- **Wildcards inside quotes** are punctuation: `"*test*"` searches for the word `test`.
- **Free text** searches `message`, `@title`, `@error.message` and `@error.stack`. It splits on
  Unicode word boundaries, so `version.2` is two words and `my.friend` one.

### 6.6 The model, construct by construct

Each construct is held to three references:

- **Docs:** whether Datadog's documentation describes it.
- **VRL:** whether VRL's grammar accepts the text. This is an accept-or-reject verdict only: VRL
  accepts `CIDR(@ip, 10.0.0.300)` as a free-text term followed by a group, for example.
- **Published uses:** how many of the 3,229 queries Datadog publishes use it (section 11).

| Construct | Example | Docs | VRL | Published uses | Model |
|---|---|:-:|:-:|--:|---|
| Free-text term | `authentication` | ✅ | ✅ | 757 | |
| Phrase | `"hello world"`, `""` | ✅ | ✅ | 300 | Curly quotes are not quotes (`datadog_curly_quote`) |
| Attribute | `@evt.outcome:FAILURE` | ✅ | ✅ | 2,042 | |
| Tag or reserved attribute | `source:okta` | ✅ | ✅ | 1,458 | A dotted bare key is a hint (`datadog_unknown_attribute`, 58 uses) |
| Calculated field | `#duration_ms:>500` | ✅ | ✅ | 0 | A warning in profile `rule` (`datadog_calculated_field_in_rule`) |
| `AND`, `OR`, implicit AND | `a OR b c` | ✅ | ✅ | 70 / 625 / most | AND binds tighter than OR (`datadog_mixed_boolean`) |
| `NOT`, `NOT(` | `NOT(CIDR(…))` | ✅ | ✅ | 6 | |
| `-` exclusion | `-@level:Error`, `-(…)`, `-"…"` | ✅ | ✅ | 142 | A space after it is a warning (`datadog_detached_operator`) |
| `+` prefix | `+@a:1` | | ✅ | 0 | Parsed; never used |
| Grouping | `(a OR b)` | ✅ | ✅ | 71 | |
| Value group | `env:(prod OR test)`, `@code:(>=400 <500)` | ✅ | ✅ | 546 | Takes comparisons, ranges and `-*` |
| Wildcards | `web*`, `a?b`, `a**b` | ✅ | ✅ | 490 / 8 / 4 | Literal inside quotes (`datadog_wildcard_in_phrase`) |
| Escaped space | `waiting\ un*` | ✅ | ✅ | 11 | |
| Existence | `@attr:*`, `-@attr:*` | ✅ | ✅ | 244 | `_exists_:` is Observability Pipelines only (`datadog_pipelines_only`) |
| Comparison | `@duration:>=100ms` | ✅ | ✅ | 48 | Duration units are numbers |
| Range | `[400 TO 499]`, `{200 TO 299}` | ✅ | ✅ | 112 / 2 | `TO` in upper case; mixed bounds are a warning |
| `CIDR()` | `CIDR(@network.client.ip, 10.0.0.0/8, fc00::/7)` | ✅ | as text only; refused with an IPv6 `::` | 8 | IPv4 and IPv6 blocks checked |
| Full text, match all | `*:hello`, `*:*` | ✅ | ❌ / ✅ | 4 / 1 | `*:term` is a warning in rule queries |
| Space after `:` | `env: prod` | | ✅ | 15 | Accepted |
| Unescaped `:` in a value | `@usr.id:system:serviceaccount:x` | ❌ (escape it) | ❌ | 3 | A warning (`datadog_unescaped_colon`) |
| `&&`, `\|\|` as operators | `a && b` | ❌ (escape them) | ✅ | 0 | A warning (`datadog_symbol_operator`) |
| Lower-case operators | `@a:1 and @b:2` | ❌ | ❌ | 1, a bug | A warning between field clauses or in a value group (`datadog_lowercase_operator`); between free-text words it is just a word |
| Regex, fuzzy, boost | `foo~2` | ❌ | ❌ | 0 | An error (`datadog_regex`) |

The model departs from VRL in two directions, both following Datadog's docs and published
queries:

- **The model accepts what VRL refuses:** `*:term`, IPv6 blocks in `CIDR()`, and a value
  starting with `+`.
- **The model warns where VRL accepts:** `&&` and `||` between clauses, and the pipelines'
  `_exists_:`.
- **The model refuses what VRL accepts:** stacked modifiers (`NOT NOT a`, `-NOT a`), which no
  published query uses.

### 6.7 Diagnostics

| Code | Severity | Fires on | Example |
|---|---|---|---|
| `datadog_parse_error` | error | Unbalanced brackets, a dangling operator, an empty group, `field:` with no value, two modifiers | `service:(web OR api`; `@user:`; `--a` |
| `datadog_unescaped_special` | error | An unescaped `! < >` in a term, or a value starting with an unescaped `-` | `foo!bar`; `@x:-1` |
| `datadog_regex` | error | `~` or `^` in a term | `@msg:foo~2` |
| `datadog_cidr` | error | `CIDR` without an `@attribute` first, or with an argument that is not an IPv4 or IPv6 CIDR block | `CIDR(network.client.ip, 10.0.0.0/8)`; `CIDR(@ip, 10.0.0.300)` |
| `datadog_range` | error, or warning for mixed bounds | A malformed range or a lower-case `to`; mixed bounds | `@x:[1 to 5]`; `@x:[1 TO 5}` |
| `datadog_mixed_boolean` | warning | An OR beside an implied or written AND, without parentheses | `service:x status:error OR warning` |
| `datadog_lowercase_operator` | warning | `and`, `or`, `not` between field clauses or inside a value group | `@a:1 and @b:2`; `@t:(k OR n or E)` |
| `datadog_curly_quote` | warning | `“…”` | `@evt.name:“Console Login”` |
| `datadog_wildcard_in_phrase` | warning | `*` or `?` touching a word inside quotes | `"*mimikatz*"` |
| `datadog_unescaped_colon` | warning | An unescaped `:` in a value. The docs say to escape it, though Datadog's own content sometimes does not | `@usr.id:system:serviceaccount:x` |
| `datadog_symbol_operator` | warning | `&&` or `\|\|` between clauses | `a && b` |
| `datadog_detached_operator` | warning | `-` followed by a space | `- @login_type:k` |
| `datadog_full_text_in_rule` | warning | `*:term` in profile `rule` | `*:mimikatz` |
| `datadog_calculated_field_in_rule` | warning | `#name` in profile `rule` | `#duration_ms:>500` |
| `datadog_pipelines_only` | warning | Observability Pipelines syntax: `_exists_:`, `_missing_:`, a quoted field name | `_exists_:service`; `"service.status":disabled` |
| `datadog_unknown_attribute` | hint | A dotted bare key, which is searched as a tag where an attribute was probably meant. With catalogs, also an `@attribute` that no catalog knows | `evt.name:ConsoleLogin` |

### 6.8 Highlighting

No capture is added to `highlights/spec.toml`.

| Token | Example | Capture |
|---|---|---|
| Attribute path, tag key, reserved attribute | `@evt.outcome`, `source` | `property` |
| Calculated field | `#duration_ms` | `variable` |
| Field separator, comparison, exclusion, wildcard | `:`, `>=`, `-`, `*` | `operator` |
| Boolean | `AND`, `OR`, `NOT` | `keyword` (TextMate: `keyword.operator.logical`, as Lucene's `tm_extras:logical`) |
| Range keyword | `TO` | `keyword` |
| `CIDR` | `CIDR(` | `function.builtin` |
| CIDR block, escape | `10.0.0.0/8`, `\:` | `constant` |
| Phrase | `"hello world"` | `string` |
| Number, with or without a unit | `400`, `100ms` | `number` |
| Brackets, comma | `( ) [ ] { }`, `,` | `punctuation.bracket`, `punctuation.delimiter` |
| Error node | | `error` |

The YAML wiring:

- **`platform_field_language`** (`crates/opentide-tide/src/lib.rs`). `PlatformId::Datadog`
  answers `["queries", <index>, "query"]`, as Exabeam answers `["sequences", <index>, "query"]`.
- **`EMBEDDED_QUERIES`** (`crates/opentide-highlight/src/lib.rs`). This TextMate table lists only
  fixed key paths, and Exabeam's list-item queries are not in it. Datadog starts the same way:
  semantic tokens colour its queries, and a list-item TextMate injection for both platforms is a
  follow-up.
- **Conditions and `message` templates are not a language.** They get no tokens in 1.0, as
  Graylog's conditions get none today. Colouring them would need a semantic-token hook in the
  platform model; that is a follow-up for both platforms.

### 6.9 Catalogs

| Catalog | Source | Licence | Holds |
|---|---|---|---|
| Reserved and standard attributes | docs.datadoghq.com/standard-attributes | Facts only; summaries written here (ADR 0013) | `@network.client.ip`, `@usr.email`, `@evt.name`, `@evt.outcome`, `@http.status_code`, … with their types |
| Source pipelines | DataDog/integrations-core `*/assets/logs/*.yaml`: 408 pipeline files with test samples | BSD-3-Clause, with its `NOTICE` beside the catalog and in `pyproject.toml`'s `license-files` | `source:` values and each source's attribute paths, for completion and `datadog_unknown_attribute` |
| Template variables | docs.datadoghq.com/security/notifications/variables | Facts only | `{{severity}}`, `{{rule_name}}`, `{{events_matched}}`, `{{@attr}}`, `{{#is_match}}`, … |

## 7. Compiling a block

### 7.1 Mapping

| Tide | Datadog rule body |
|---|---|
| `name` | `name` |
| `enabled` and the strategy (8.3) | `isEnabled` |
| (always) | `type: log_detection` |
| `queries[]` | Each query compiles as follows: <ul><li>`query`, `name`; `from` → `dataSource`; `group_by` → `groupByFields`; `keep_missing_groups` → `hasOptionalGroupByFields`.</li><li>The measure becomes `aggregation` and its field: none → `count`; `count_distinct` → `cardinality` + `distinctFields`; `sum` or `max` → `metrics: [field]`; `new_value` → `new_value` + `metrics`.</li><li>Impossible travel → `geo_data` + `metrics: ["@network.client.geoip"]`.</li></ul> |
| `detection` | `options.detectionMethod` and `options.evaluationWindow`; the method's settings go into `newValueOptions`, `anomalyDetectionOptions` or `impossibleTravelOptions`, each in the unit that property takes |
| `cases[]` | `cases[]`. `severity`, or `response.alert_severity` mapped (Informational → `info`, Low → `low`, Medium → `medium`, High → `high`, Critical → `critical`), becomes `status`; `notify` aliases resolve into `notifications` |
| `signal` | `groupSignalsBy` when set, `options.keepAlive`, `options.maxSignalDuration`, `options.decreaseCriticalityBasedOnEnv`, `hasExtendedTitle` |
| `message` | The block's, else derived (7.3) |
| tags | Derived (7.4), plus the block's and the tenant's |

### 7.2 The request for the complete block

The complete block (5.2) has `status: PRODUCTION`, which the default `deployment.toml` maps to
`RELEASE`. On a tenant whose `soc` alias is `@slack-soc-alerts`, its first deploy sends:

```http
POST https://api.datadoghq.eu/api/v2/security_monitoring/rules
DD-API-KEY: …
DD-APPLICATION-KEY: …
Content-Type: application/json
```

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
  "message": "{{@usr.email}} failed to log in {{events_matched_per_query.failed}} times, then succeeded.",
  "tags": ["team:identity", "source:okta", "tactic:ta0006-credential-access",
           "technique:t1110-brute-force", "security:attack",
           "opentide_uuid:2b0d7c1e-0b55-4f0e-9d0b-3c0f2a8f9a11"]
}
```

Under a `PREVIEW` status, such as `STAGING`, the same body has `"notifications": []` and the tag
`opentide_strategy:preview` (8.3).

### 7.3 The derived message

When the block has no `message`, the compiler writes one in the sections Datadog's own rules use:

- `## Goal`, from `description`;
- `## Strategy`, from the queries and cases, in words;
- `## Triage and response`, from `response.procedure`.

Text taken from the rule is escaped, so that a `{{` in a description is not read as a template.

### 7.4 Derived tags

Derived tags follow Datadog's own conventions and opentide's shared ATT&CK resolution:

- **`source:<x>`**, for each distinct `source:` the queries name.
- **`technique:<t id>-<slug>`**, for each technique the rule inherits. These come through the shared
  resolver (`inherited_techniques`, `crates/opentide-compile/src/deploy.rs`), taking the parent
  technique for a sub-technique, as Datadog's default rules do.
- **`tactic:<ta id>-<slug>`**, for each stage of each inherited technique, through
  `cx.attack.stages` and `attack::tactic` (`crates/opentide-compile/src/attack.rs`), as Sysdig's
  `attack_tags` and Elastic's `threat` derive theirs.
- **`security:attack`.**
- **`opentide_uuid:<uuid>`.** It helps people find opentide's rules in Datadog, and is advisory
  only: the deployment-state shard stays the only proof that a rule is opentide's to change or
  remove.

Every derived tag is lower-case. A tag written in the block must already be lower-case, or it is
refused (`datadog_tag`).

## 8. The connector

### 8.1 Tenant (`platforms/datadog.toml`)

```toml
[platform]
enabled = false
name = "Datadog Cloud SIEM"
description = "Datadog Cloud SIEM detection rules."

# Datadog Cloud SIEM through the v2 Security Monitoring API. site is the Datadog site
# (datadoghq.com, us3.datadoghq.com, us5.datadoghq.com, datadoghq.eu, ap1.datadoghq.com,
# ap2.datadoghq.com, uk1.datadoghq.com, ddog-gov.com, us2.ddog-gov.com); calls go to
# https://api.<site>, or to api_url when set (a new site, a proxy). api_key and app_key are sent
# as DD-API-KEY and DD-APPLICATION-KEY. The application key needs
# security_monitoring_rules_read and security_monitoring_rules_write (validation needs write),
# and logs_read_data for opentide query. Use a service account's scoped key. The rule id is kept
# in .opentide/states/deployment/ (commit it).
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

### 8.2 Calls

Paths are relative to `https://api.<site>/api/v2` (or the tenant's `api_url`). Every call here is
generally available.

| opentide | Call | Application-key scope | Result |
|---|---|---|---|
| `validate query --live` on a block, and before each create or update | `POST /security_monitoring/rules/validation` with the compiled body | `security_monitoring_rules_write` | 204: valid. 400: `datadog_rule_invalid`, with Datadog's `errors[]` |
| `validate query --live` on a `.datadog` file or a hunt (profile `search`) | `POST /logs/events/search` with the query, a one-minute window and `page.limit: 1` | `logs_read_data` | A 400 places Datadog's error on the query. A search is checked as a search, not wrapped in a rule, so `*:term` and `#name` are judged as Log Explorer judges them |
| Deploy, no stored id | `POST /security_monitoring/rules` | `…_rules_write` | 200 with the rule. Its `id` goes to the deployment state |
| Deploy, stored id | `GET /security_monitoring/rules/{id}`, then `PUT` the same path only if a property opentide owns differs from the compiled body (below) | `…_rules_read`, `…_rules_write` | The `PUT` sends `queries`, `cases` and `options` whole, and the `version` the `GET` returned. The spec answers a concurrent modification with **401**, which is reported as `datadog_concurrent_modification`, not as an authentication failure |
| `DISABLEMENT` | `GET`, then `PUT /security_monitoring/rules/{id}` with `isEnabled: false` and the `version` | `…_rules_read`, `…_rules_write` | |
| `DELETION` | `DELETE /security_monitoring/rules/{id}` | `…_rules_write` | 204. A 404 is `datadog_rule_missing`: already gone |
| Drift, `doctor` | `GET /security_monitoring/rules/{id}`, compared with the compiled body; `GET …/rules/{id}/version_history` names who changed what | `…_rules_read` | |
| `opentide query` | `POST /logs/events/search` with `filter.query`, `from`, `to`, `indexes` and `storage_tier` | `logs_read_data` | Paged by the cursor in `meta.page.after`, up to 5,000 events a page |

The deployment state keeps only the id (`deployment.state::1.0`). Drift is therefore found by
comparing the rule Datadog holds with the compiled body, as Sentinel's unchanged check compares, not
by a stored version.

The comparison covers only the properties opentide writes, normalised the same way on both
sides:

- **Compared:** `name`, `isEnabled`, `queries`, `cases`, `options`, `message`, `tags`,
  `groupSignalsBy` and `hasExtendedTitle`.
- **Not compared:** properties the response adds (`id`, `version`, `createdAt`, `defaultTags`,
  `customMessage`, `filters`, …).
- **Absent equals default.** A property the body leaves out equals the response's default
  (`hasOptionalGroupByFields: false`, an empty `distinctFields`).
- **Unordered lists.** Tags are compared as a set; queries and cases keep their order.

A fake-API test holds that an unchanged rule sends no `PUT`.

A rule whose `GET` answers `isDeleted: true` is treated like a 404.

### 8.3 Deploy lifecycle, by strategy

The block's `status` maps to a strategy through `deployment.toml`, as on every platform.

| Strategy | What deploy does on Datadog |
|---|---|
| `INERT` | Nothing |
| `PREVIEW` | Creates or updates the rule **enabled, with no notifications on its cases**, and tags it `opentide_strategy:preview` |
| `RELEASE`, `UNIVERSAL` | Creates or updates the rule enabled, with its notifications |
| `DISABLEMENT` | Sets `isEnabled: false`. The rule and its history stay |
| `DELETION` | Deletes the rule. Deploy never deletes a default rule, or a rule whose id it does not hold |

What `PREVIEW` means on Datadog, and what it does not:

- **Signals still appear.** Datadog has no mode that runs a rule without creating signals, so a
  preview rule's signals show in the Signals Explorer.
- **Notification rules may still page someone.** Datadog's notification rules route signals
  whatever a rule's own notifications say. The platform page tells teams to exclude
  `opentide_strategy:preview` from their notification rules.
- **A CI preview run cannot create rules.** Datadog keeps ids in the deployment state, so a CI run
  other than the production job refuses every create, `deployment_state_unpersisted`. That
  includes recreating a rule that has gone. A preview run updates rules that already exist; new
  rules are created by the production job, or by a deploy run outside CI.
- **Promotion may restart learning.** Datadog's docs say that "if the detection rule is modified,
  the learning period restarts at day 0". Promoting a preview rule changes its notifications and
  tags, which may restart a `new_value` or `impossible_travel` rule's learning just as it goes
  live (open question 10; section 14).

Every create and update is validated first (`POST /rules/validation`), so an invalid body is
reported before anything changes.

**Retries.** Datadog waits out its own rate limits, as Bitdefender, Exabeam and Google SecOps do:

- A 429 on any call is retried after the seconds `X-RateLimit-Reset` gives: the seconds until the
  rate-limit window resets (Datadog's rate-limits page). It is retried at most three times. A 429
  means Datadog refused the request, so resending even a create is safe.
- When the reset is more than 120 seconds away, the call is not resent and is reported as
  `datadog_rate_limited`.
- A create that gets no answer, or a 5xx, is not resent (`datadog_create_unconfirmed`).
- Every other call follows the shared retry policy (`docs/usage/configuration.md`, "Retries").

**A stored id whose rule is gone** (404, or `isDeleted`) is recreated by a run that may create, and
reported as `datadog_rule_recreated`.

### 8.4 Failure codes

| Code | When |
|---|---|
| `datadog_tenant_unauthorized` | A 403, or a 401 that is not a concurrent modification |
| `datadog_tenant_unreachable` | DNS, TLS or a timeout |
| `datadog_site` | A `site` outside the known list, with no `api_url` |
| `datadog_rate_limited` | A 429 after the retries |
| `datadog_rule_invalid` | A 400 from `/rules/validation` or a write |
| `datadog_create_unconfirmed` | A create that got no answer, or a 5xx; it is not resent |
| `datadog_concurrent_modification` | A 401 on a `PUT`: the rule changed since the `GET` |
| `datadog_rule_missing` | The stored id is gone (on `DELETION`) |
| `datadog_rule_recreated` | The stored id was gone, and deploy created a new rule |
| `datadog_rule_default` | The stored id is a default rule (`isDefault: true`): opentide never changes one |

### 8.5 External id

The deployment state keeps Datadog's rule id as text, with no shape check:
`ExternalId::Text { pattern: None }`, as CrowdStrike has.

- Every id in Datadog's own content is three groups of three characters (`m0o-hto-lkb`,
  `def-000-u7q`).
- The spec's examples also show `abc-123`, and no source states the format.

A pattern would refuse real shards if the format differs, so none is set until phase 0 confirms it
(open question 4).

## 9. Wiring

| Area | Files |
|---|---|
| Registry row | `crates/opentide-schema/src/platforms.rs`: `id: "datadog"`, `label: "Datadog Cloud SIEM"`, `configuration_name`, `config_class: "DatadogConfig"`, `external_id: ExternalId::Text { pattern: None }`, `deploys`, `compiles_offline`, `live_check`, `query_runner`, `runner_languages: &["datadog"]`, `offline_languages: &["datadog"]`, `query_file_suffixes: &["datadog"]` |
| Model and constraints | `crates/opentide-schema/src/objects/platform/datadog.rs` and `datadog/condition.rs`; the registration in `platform/mod.rs`; the required keys in `schema.rs` |
| Templates | `src/opentide/schemas/data/platform_templates/datadog.template.yaml`; `src/opentide/data/configurations/platforms/datadog.toml` |
| Compiler | `crates/opentide-compile/src/datadog.rs`, `modifiers.rs`, `preview.rs`, the platform docs generator |
| Connector | `crates/opentide-connectors/src/datadog.rs`, with fake-API tests and cassettes |
| Engine | The new `crates/opentide-datadog/`, wired as listed in the next table |
| Command line and MCP | `new`, `setup --datadog`, `doctor`, `query`, `validate_live`, MCP `validate_query` and `run_query` |
| Diagnostics pages | `src/opentide/data/diagnostics/datadog_*.md` |
| Docs | The six pages `AGENTS.md` lists under "Platforms"; `docs/usage/concepts/deployment-state.md` (the platforms that keep ids); `docs/usage/configuration.md` ("Retries"); `docs/engine/DATADOG.md` |
| Companions | opentidehq/skills: a Datadog platform skill and `coverage.json`. opentidehq/vscode-extension: the new language |

The engine wiring follows the add-language skill. These are the items it asks to decide up front:

| Item | Decision |
|---|---|
| `LanguageId::Datadog` | A breaking change to the facade (`opentide`), a minor bump while 0.x, with a **Breaking** entry in `crates/CHANGELOG.md` |
| Codes and registries | The codes in `opentide-core`; the keywords and `EMBEDDED_QUERIES` in `opentide-highlight`; `platform_field_language` and hunts with `system: datadog` in `opentide-tide`; `opentide-analysis` |
| The VRL oracle | `scripts/engine/oracles/datadog/`, its exceptions in `crates/testdata/oracles/exceptions.toml` (`[[datadog]]`), a job in `.github/workflows/oracle.yml`, and VRL's licence in the licence scan |
| Corpus gate | The language has no comment syntax. As for Lucene and Exabeam, each corpus file's tag sits on a `#` first line that the gate drops before parsing (`crates/opentide-analysis/tests/corpus_gate.rs`), so it never meets a calculated field |
| Fuzzing and budgets | A fuzz target, and a row in the throughput budgets |

`cargo test -p xtask --test language_wiring` and `xtask/tests/platform_docs.rs` list whatever is
missing.

## 10. Content to start from

There is **no sizeable open corpus of Datadog Cloud SIEM rules in Datadog's own format**:

- **Datadog's default rules** (about 970 Cloud SIEM rules) are published as Goal, Strategy and
  Triage text, without their queries. A machine-readable copy needs an account.
- **Datadog's own detection-as-code repository** is internal (per its 2024 blog post).

What exists:

| Source | Licence | What it gives | Use |
|---|---|---|---|
| **The Datadog-published query corpus** (section 11) | BSD-3-Clause (docs and integrations, 2,800 queries); MPL-2.0 (Terraform provider, 95); Apache-2.0 (API clients and two DataDog repositories, 95); Datadog's site terms (blog and Security Labs, 239) | 3,229 literal log-search queries, each with its source and licence | **The conformance corpus.** BSD-3 and Apache-2.0 queries are vendored with their notices. MPL-2.0 files are kept apart, unmodified. Blog and Security Labs queries are measured, not vendored |
| integrations-core `*/assets/logs/` | BSD-3-Clause | 408 pipeline files: sources, attribute remaps, sample logs | Catalogs (6.9); samples for rule tests |
| integrations-extras `*/assets/security/*.json` | BSD-3-Clause | 11 rules in Datadog's export format (AppOmni, Bottomline, Contrast) | API body fixtures and seed rules |
| DataDog/documentation `request.*Rule*.json`; datadog-api-client `examples/v2/security-monitoring` | BSD-3-Clause; Apache-2.0 | 42 synthetic request bodies covering every rule type and method | API body fixtures |
| terraform-provider-datadog test cassettes (`TestAccDatadogSecurityMonitoringDefaultRule_*`) | MPL-2.0 files recording Datadog's proprietary rules | 199 default rules, 153 distinct queries | **Measured, not vendored**, as Exabeam's content hub: an ignored test reads a local checkout |
| vectordotdev/vrl `src/datadog/search/` | MPL-2.0 | The grammar of the pipelines' dialect | A differential oracle, not vendored |
| DataDog/stratus-red-team, grimoire, threatest | Apache-2.0 | 103 cloud attack techniques, 36 recorded detonation logs, signal assertions | Seed rules written against them, with their logs as test samples; a manual tenant run |

Seed rules for opentide's examples come from three places, none of them converted from another
format:

- the 11 BSD-3 rules in Datadog's own format;
- rules written here for Stratus Red Team's techniques;
- the Cloud SIEM examples in Datadog's docs.

## 11. Evidence: the model against Datadog's own queries

### 11.1 The corpus

The corpus gathers every literal log-search query Datadog publishes, from these sources:

- the documentation repository: the search syntax, Cloud SIEM, RUM, CI, Audit, Events and
  Observability Pipelines pages, and the API reference;
- integrations-core and integrations-extras: pipeline filters, dashboards, saved views, monitors
  and security rules;
- the Terraform provider's docs and tests;
- the five API clients' examples;
- the Datadog blog (all 2,005 posts) and Security Labs.

Each query keeps its source, pinned to a commit, and its licence. Three kinds of query are set
aside:

- **2,659 templated queries** (`$var`, `{{…}}`, `<PLACEHOLDER>`);
- **88 dashboard queries that are not log search**: 74 Monitor Summary searches and 14 event-stream
  filters, which use the legacy events syntax;
- **one legacy events query** from a blog post.

By context, the corpus holds:

| Context | Queries |
|---|--:|
| Pipeline filters, and 46 index, archive and scanner filters from the Terraform provider | 1,650 |
| Dashboards | 555 |
| Docs examples | 398 |
| Blog | 239 |
| API examples | 104 |
| Saved views | 96 |
| Observability Pipelines | 86 |
| Monitors | 48 |
| SIEM rules | 42 |
| Suppressions | 10 |
| Signal searches | 1 |

**What the corpus can and cannot show:**

- Only 42 of its queries are Cloud SIEM rule queries, and some of those are Terraform test filler
  ("does not really match much"). Half are pipeline filters.
- It holds the shape of Datadog's own queries: which constructs appear, how often, and how they are
  written.
- It says nothing about how Cloud SIEM evaluates a query. Precedence and matching are open
  question 2, which only a tenant settles.

### 11.2 Agreement

The prototype is a token-level linter for sections 5.8 and 6.4 to 6.7. It has no tree and no
grammar; the engine will have both. It was run next to VRL's grammar, compiled as an
accept-or-reject oracle. Agreement here means both accept or both refuse a query. It says nothing
about tree shape or precedence.

| Corpus | Queries | Accept/reject agreement with VRL | Prototype errors |
|---|--:|--:|--:|
| The Log Search Syntax page's examples | 28 | 27 | 0 |
| The Datadog-published corpus | 3,229 | 3,215 (99.6%) | 5 |
| The recorded default rules (measured only) | 153 | 153 | 0 |

**Every one of the 14 disagreements is a query Datadog publishes and VRL refuses:**

| Disagreement | Queries | Why |
|---|--:|---|
| `CIDR(…)` lists in pipeline filters | 3 | VRL reads `CIDR(…)` as free text and a group, and refuses these for their IPv6 `fc00::/7` (its terms cannot hold `:`). The other five uses agree only because VRL takes them as text |
| The docs' own `*:term` examples | 4 | VRL has only `*:*` |
| Values starting with `+` (`@process.args:+x`, `@data.message:+*`) | 2 | VRL refuses a leading `+`; Datadog's docs use it |
| An unescaped `:` in a value (a RUM docs example, two blog posts) | 3 | VRL refuses it; the model warns (`datadog_unescaped_colon`), since Datadog's own content writes it |
| Observability Pipelines syntax | 2 | A quoted field name (`datadog_pipelines_only`), and a term glued to a phrase (`tags:service\:"web-store"`), which the model accepts without a finding |

**The five queries the prototype rejects** are not queries a rule could hold:

- a deliberately invalid query from Datadog's API tests (`rule:[A-Invalid`);
- two Observability Pipelines-only forms (`message:*!*`);
- a RUM retention filter written `@session.view.count :> 3`;
- indicators a Security Labs article wrote as `models.litellm[.]cloud` on purpose, so they cannot
  be clicked.

**Building against the corpus changed the model in five places:**

1. A space may follow `:`.
2. Value groups take comparisons and ranges.
3. Numbers carry duration units.
4. An unescaped `:` in a value is a warning, not an error.
5. A comma has meaning only inside `CIDR()`.

The review also corrected the corpus itself. The 88 Monitor Summary and event-stream queries had
first been counted as log search, and had briefly made `tag:integration:x` look like valid log
syntax.

### 11.3 Mistakes found in Datadog's own content

| Where | Query | What it does instead | Code |
|---|---|---|---|
| A Microsoft 365 default rule, recorded by the Terraform provider | `@SourceFileName:(*.exe OR … OR *.zip OR *.rar *.7z *.cab OR *.tar …)` | In a value group a space is AND, so `*.rar *.7z *.cab` asks for a name ending in all three at once: `.rar`, `.7z` and `.cab` uploads are never detected | `datadog_mixed_boolean` |
| A Datadog blog post | `service:azure-service-bus status:error OR warning`, and the same with `throttled OR quota_exceeded` | Reads as "(this service and error) or any log containing the word warning", where `status:(error OR warning)` was meant | `datadog_mixed_boolean` |
| A Security Labs Salesforce guide | `- @login_type:(k OR n or E)` | The lower-case `or` is a term, so the group asks for `k`, or for `n`, `or` and `E` at once | `datadog_lowercase_operator`, `datadog_mixed_boolean`, `datadog_detached_operator` |

The first two depend on AND binding tighter than OR, which is why open question 2 is the first
thing to settle on a tenant.

## 12. Upgrade path

- **Within `datadog-1.x`, every addition is optional.** These include sequence rules with
  cross-rule references, scheduled and third-party rules, reference tables, default-rule tuning and
  the baseline options. Each new key comes with its own minor version. A 1.0 block stays valid and
  compiles to the same body.
- **A change of meaning is a new major version.** That includes a changed default and a renamed
  key. Both versions are registered side by side in the revision registry (ADR 0009) for at least
  one release, and the change ships with a migration (`docs/cli/migrate.md`).
- **Adopting existing Datadog rules.** A team that manages rules in the Datadog UI or in Terraform
  needs a way in.
  - **Later: an importer.** It reads `GET /rules/{id}`, or the JSON that `POST /rules/bulk_export`
    writes, and produces a Tide rule with a `datadog` block. It keeps the rule id in the deployment
    state, so the first deploy updates the rule instead of creating a second one.
  - **Until then:** a team writes the block, and adds the existing id to the rule's shard,
    `.opentide/states/deployment/<uuid>.json` (`deployment.state::1.0`), before its first deploy.
- **Leaving Terraform.** A rule managed by both Terraform and opentide is changed back and forth on
  every run. The platform page tells teams to remove a rule from Terraform's state
  (`terraform state rm`) before opentide takes it over.

## 13. Alternatives considered

| Alternative | Why not |
|---|---|
| **A fourth Lucene dialect** for the search syntax | The precedence changes the tree, and `@`, `CIDR()`, `**` and the escape rules differ. A dialect would branch the shared walk at almost every node (6.2) |
| **A block that mirrors the API**, as the Terraform resource does (`options.evaluation_window`, `aggregation`, `distinct_fields`) | It keeps the API's mixed `options` object and its interdependent aggregation properties, which constraints would then have to police. Tide blocks are read by people writing detections, so they group by meaning (5.3) |
| **Deploy through Terraform**: generate HCL and let Terraform apply it | It adds a second tool and state file, and loses opentide's per-rule state, strategies and diagnostics. Datadog's convert endpoints stay available to users who want HCL |
| **VRL as the engine**, through the `vrl` crate | VRL is a log-processing runtime with a large dependency tree. Its grammar is the pipelines' dialect: no `CIDR()` and no `*:term`, but `_exists_:`. It has no lossless tree to place highlighting and diagnostics on. It stays as an oracle |
| **`signal_correlation` in 1.0** | Datadog refuses new ones (5.6) |
| **Converting community rule sets** (Sigma and its Datadog backend) | The conversions inherit the converters' bugs, and the language should be modelled from Datadog's own definition. Datadog's published queries are enough to hold the model to |

## 14. Risks

| Risk | Mitigation |
|---|---|
| **The precedence is unverified** on Cloud SIEM. If Datadog evaluates `a OR b c` differently, `datadog_mixed_boolean` is wrong | It is a warning, and its message names the assumption. Open question 2 is phase 0's first probe |
| **Validation needs a write-scoped key**, and a key that can validate can also delete | `setup` recommends a service account's key scoped to the security-monitoring rules. `doctor` warns that the key can write (open question 7) |
| **Default rules** look like ordinary rules through the API | Deploy checks `isDefault` before any write and refuses (`datadog_rule_default`) |
| **Preview signals can reach people** through Datadog's notification rules | The `opentide_strategy:preview` tag, and the platform page's guidance to exclude it (8.3) |
| **Promotion may restart a learning period** on `new_value` and `impossible_travel` rules | Measured in phase 0 (open question 10). Promotion is a `PUT` whatever it changes. If the restart is confirmed, these two methods get no `PREVIEW` deploy: `validate` warns when their status maps to `PREVIEW`, and they are deployed at `RELEASE` only |
| **The API changes.** Datadog adds methods and properties, some in preview, and has already withdrawn `signal_correlation` | The block refuses anything outside its scope instead of passing it through. The fake-API tests pin the request bodies, and a tenant run per release catches drift |
| **Rate limits are undocumented** for these endpoints | Deploy reads `X-RateLimit-*` and waits, and never runs parallel writes against one tenant |
| **A team's pipelines remap attributes**, so the attribute catalog cannot know every field | An unknown attribute is a hint, never an error |

## 15. Plan

| Phase | Delivers | Exit criteria |
|---|---|---|
| 0. Specs and probes | This RFC numbered in opentidehq/specifications; the `datadog-1.0` language and platform specs with fixtures; a trial tenant and the probe set for the open questions | Specs reviewed; the probes recorded |
| 1. Engine | `opentide-datadog`: lexer, Pratt grammar, `.ungram`, profiles, diagnostics, highlighting, catalogs, the corpus gate, the VRL differential, a fuzz target, a throughput budget | `language_wiring` green. On the published corpus, every error and every VRL disagreement explained, as in 11.2. The recorded default rules measured |
| 2. Platform | Model, constraints, compiler, connector (validate, deploy, disable, delete, drift), the registry row, `setup --datadog`, `opentide query`, docs, explain pages, snapshots | `scripts/ci-local.sh --full`; a tenant run recorded like the Defender one; the companions |
| 3. Depth | Sequence rules and cross-rule correlation; rule tests; scheduled and third-party rules; default-rule tuning; the importer; message template checks | Each behind its own spec minor version |

## 16. Open questions

Each is settled by a probe on a trial tenant in phase 0, unless noted.

1. **The language id.** `datadog` follows Exabeam's precedent and is what users search for.
   `ddsearch` would leave room if DDSQL or SECL ever became engine languages. The draft picks
   `datadog`: SQL is out of scope, and SECL belongs to another product. This is a naming decision
   for review, not a probe.
2. **Precedence and operators.** Do Log Explorer and Cloud SIEM bind AND tighter than OR, as VRL
   does? Are `&&`, `||` and `!` operators? Probe: `POST /rules/test` with sample events that tell
   the readings apart. The answers are recorded as a probe set, like Graylog's oracle.
3. **The condition grammar.** Do conditions accept parentheses or `==`? How do `&&` and `||` bind
   together? How is the editor's "then" condition serialised?
4. **The rule id format** (8.5), and whether `def-000-` always marks a default rule. Deploy relies
   on `isDefault` either way.
5. **Limits.** The maximum number of queries and cases per rule (historical jobs cap both at 10),
   the maximum query length, and the rate limits.
6. **What each accepted-but-undocumented form does:**
   - `*:term`, `_exists_`, and open or mixed range bounds in rule queries;
   - an unescaped `:` in a value, a space after `:`, and duration units in comparisons;
   - `detectIpTransition`, and the spec's rule that it or `baselineUserLocations` must be true,
     which Datadog's own example does not follow;
   - the `new_value` editor options "for all new values" and "after the first seen value", in terms
     of `learningMethod`, `learningDuration` and `learningThreshold`;
   - the anomaly `bucket`, `learning` and `tolerance` defaults, and whether `window` may be shorter
     than `bucket`.
7. **A write-scoped key for validation.** Should `setup` recommend a separate validation key, and
   should `doctor` warn when a key that only needs to validate could also delete? A product
   decision, not a probe.
8. **Suppressions.** Should suppression rules (`/configuration/suppressions`) be modelled as part
   of the block (`suppressions[]`, deployed with the rule, as Datadog's own team does) or as their
   own Tide object? A design decision for a follow-up RFC.
9. **Signals as a data source.** Which attribute of a signal names the rule that raised it, so that
   a `from: signals` query, and later a sequence step, can select one rule's signals?
10. **Learning restarts.** Does changing only a rule's notifications or tags restart a `new_value`
    or `impossible_travel` learning period?

## 17. References

- API reference: https://docs.datadoghq.com/api/latest/security-monitoring/
- OpenAPI v2 (the `x-unstable` marker means preview): https://github.com/DataDog/datadog-api-client-python/blob/master/.generator/schemas/v2/openapi.yaml
- Terraform provider, the `signal_correlation` test skip: https://github.com/DataDog/terraform-provider-datadog/blob/master/datadog/tests/resource_datadog_security_monitoring_rule_test.go
- Log search syntax: https://docs.datadoghq.com/logs/explorer/search_syntax/
- Creating rules and conditions: https://docs.datadoghq.com/security/cloud_siem/detect_and_monitor/custom_detection_rules/create_rule/
- Sequence rules: https://docs.datadoghq.com/security/cloud_siem/detect_and_monitor/custom_detection_rules/sequence/
- Suppressions: https://docs.datadoghq.com/security/cloud_siem/detect_and_monitor/suppressions/
- Notification variables: https://docs.datadoghq.com/security/notifications/variables/
- Calculated-field formulas: https://docs.datadoghq.com/logs/explorer/calculated_fields/formulas/
- Observability Pipelines search syntax: https://docs.datadoghq.com/observability_pipelines/search_syntax/logs/
- DDSQL: https://docs.datadoghq.com/ddsql_reference/
- Sites: https://docs.datadoghq.com/getting_started/site/
- API and application keys: https://docs.datadoghq.com/account_management/api-app-keys/
- Rate limits: https://docs.datadoghq.com/api/latest/rate-limits/
- Logs search: https://docs.datadoghq.com/api/latest/logs/search-logs-post.md
- Terraform resource: https://registry.terraform.io/providers/DataDog/datadog/latest/docs/resources/security_monitoring_rule
- Detection as code for Cloud SIEM (2025-06-11): https://www.datadoghq.com/blog/detection-as-code-cloud-siem/
- How Datadog uses detection as code (2024-10-11): https://www.datadoghq.com/blog/datadog-detection-as-code/
- VRL's Datadog search grammar: https://github.com/vectordotdev/vrl/tree/main/src/datadog/search
