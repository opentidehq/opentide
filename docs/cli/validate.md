---
title: opentide validate
description: Object validation (schema, UUIDs, uniqueness, configuration, queries) and platform query validation.
---

# opentide validate

Validates detection objects and their queries: does the catalogue deploy? `validate` reports what a platform or opentide would reject. Style that would not stop a deploy (a slow query shape, a missing recommended key) is [`opentide lint`](./lint.md)'s.

## Object validation (default)

```bash
opentide validate
opentide validate --strict
opentide validate --file objects/rules/example.yaml
opentide validate --uuid <uuid> --uuid <uuid2>
opentide validate --type rule
opentide validate --check schema
opentide validate --fix
opentide validate --fix --dry-run
opentide validate --watch
opentide validate --queries warn
opentide validate --queries off
opentide validate --check queries
```

### Options

| Flag | Purpose |
|------|---------|
| `--check` | Run a single check: `id-uniqueness`, `uuid-format`, `schema`, `configuration`, `cve`, `sharing-config`, `queries` |
| `--queries` | How the `queries` check reports a query the platform would reject: `error` (the default), `warn` (a warning: the run passes unless `--strict`) or `off` (queries are not checked). See [Queries](#queries) |
| `--file` | Validate one YAML file — repo-relative path, absolute path, or bare file name (see [Selecting a file](#selecting-a-file)). Repeatable: each `--file` adds a file to the scope |
| `--uuid` | Validate specific UUIDs (repeatable) |
| `--type` | Filter by object type (repeatable) |
| `--strict` | Treat warnings as failures (exit `1`), except `platform_not_enabled` |
| `--fix` | Apply every safe fix, then validate again (see [Fixing typos](#fixing-typos---fix)) |
| `--dry-run` | With `--fix`: print the edits as a unified diff and change nothing |
| `--watch` | Validate again each time an object file is saved, until Ctrl-C (see [Watching](#watching---watch)) |
| `--format` | `text` (code frames, the default), `sarif` (SARIF 2.1.0 for code scanning) or `codequality` (GitLab Code Quality). See [Reports and CI annotations](#reports-and-ci-annotations) |
| `--output` | Write the `--format` report to this file and still print the code frames. Without it the report is all of stdout. Required with `--json`. Needs `--format sarif` or `codequality`: with `text` it exits `2` |

`--strict` fails warning runs with exit `1`. Without it, warnings are reported in output and the process still exits `0`. The one exception is `platform_not_enabled` (see [Platforms this workspace has not enabled](#platforms-this-workspace-has-not-enabled)), which `--strict` reports without failing. Validation failures in `--json` mode include the complete report before the process exits.

`configuration` runs by default on a full run. It checks every merged configuration file the CLI reads (`paths.toml`, `deployment.toml`, `schema.toml`, `visibility.toml`, `documentation.toml`, and each built-in `platforms/<id>.toml`) against its [model](../sdk/configuration.md), so a misspelt key fails `validate` instead of the next `deploy` or `generate docs`. Each issue's `context.file` names the file and `field_path` the key, for example `unknown_key` at `promotion.enabeld` in `deployment.toml`. A malformed `[[responders]]` entry and an undeclared visibility asset are warnings, as the loaders skip them; a run narrowed with `--file`, `--uuid` or `--type` skips this check unless `--check configuration` asks for it. Values are never printed.

`sharing-config` is off unless you pass `--check sharing-config`. It checks the merged `sharing.toml`: required MISP fields, block names, unknown keys, `max_tlp`, organisation UUIDs, object types, and a `sharing/` configuration directory. `opentide share push` runs the same check. A literal API key is a warning and is never printed.

Without `--json`, each issue and warning prints as a code frame, grouped by file and ordered by line: `severity[code]: message`, the path with `:line:column`, the line from the file with the value underlined, and `help` and `note` lines. One line then counts them: `✓ 3 objects valid · 0.9s`, or `✗ 2 errors in 1 file · 3 objects checked · 0.9s` on stderr. A typo in a vocabulary value:

```text illustrative
error[vocab_unknown]: 'clearr' is not a TLP value
  ╭─▶ objects/rules/sentinel-kql-rule.yaml:8:8
  │
7 │   modified: 2026-01-02
8 │   tlp: clearr
  │        ━━━━━━ not in tlp::1.0
  │
  ╰─ help: did you mean 'clear'?

✗ 1 error in 1 file · 3 objects checked · 0.9s
→ opentide explain vocab_unknown · how to fix it
→ opentide validate · check again
```

The sample is illustrative because the outcome line carries the run time. A failed run ends with what to run next, the page of the first finding's code and `validate` again; `--json` lists them under `next_actions`. A value that differs from an allowed one only in case or in its separators (`AMBER`, `localised_incident`) gets a `safe` fix. On a terminal, a long message wraps between words and a long path is shortened in the middle with `…`. Paths are relative to the current directory when you run inside it, otherwise to the workspace; in a terminal they are links your editor opens (`OPENTIDE_LINKS=file|vscode|cursor|none` picks the scheme). `opentide explain <code>` prints what a code means and how to fix it; [Diagnostic codes](./diagnostics.md) lists them all.

One cause is one finding: a dangling reference such as `detection_model` is reported as `invalid_ref` only, not also as `vocab_unknown`.

### Reports and CI annotations

```bash
opentide validate --strict --format sarif --output opentide-reports/validate.sarif
opentide validate --format codequality > gl-code-quality-report.json
```

`--format sarif` writes SARIF 2.1.0: one run whose rules are the [diagnostic codes](./diagnostics.md), each with its `opentide explain` page as help, and one result per finding with its region (columns count Unicode code points), the object's UUID as its logical location and, for a vocabulary typo, its fix. `--format codequality` writes the Code Climate JSON GitLab reads from `artifacts:reports:codequality`. Paths are relative to the CI checkout when opentide runs in CI, else to the workspace. A finding that names no file is left out of both. The exit code is the same as without `--format`.

In a GitHub Actions or Azure Pipelines job, each finding is also written to stdout as an annotation (`::error file=…,line=…,col=…,title=<code>::<message>`, or `##vso[task.logissue …]`), and the outcome line and a table of findings go to the job summary; GitLab gets the summary as `opentide-reports/summary.md`. `--json` turns these off. See [CI/CD](../usage/workflows/ci-cd.md#annotations-summaries-and-reports).

### Diagnostic fields

Each entry of `report.issues` and `report.warnings` keeps its keys (`yaml_line` stays zero-based, `file_path` stays absolute) and gains:

| Key | Value |
|-----|-------|
| `path` | The file, relative to the workspace, with `/` separators. `null` when no file is at fault |
| `line` | One-based line of what the frame points at. `null` when unknown. Not always `yaml_line + 1`: for a block value (a mapping or a list) it is the line of the key, where `yaml_line` is the block's first child; for a missing field it is the key of the mapping the field belongs in |
| `column`, `end_column` | One-based columns of the value (of the key, for a block, a missing field or an unknown key); `end_column` is just past the last character. Columns count Unicode code points (`🔥` is one column), not UTF-16 code units. Best effort, `null` when unknown |
| `help` | What to do, in prose (`did you mean 'clear'?`), or `null` |
| `fix` | `null`, or `{ "safe": bool, "edits": [{ "line", "column", "end_line", "end_column", "replacement" }] }`: replace the text from (`line`, `column`) up to (`end_line`, `end_column`). Every suggested value gets a fix. `safe` is `true` only when the two values spell the same word (they differ in case, spaces, `-` or `_`) and neither has a digit, so an ATT&CK id, a UUID or `clearr` → `clear` is left for a person or an agent to confirm. A reference fix is never safe |
| `explain` | `opentide explain <code>` |

`summary` counts `objects`, `errors`, `warnings`, `files` (files with an error), `warning_files` (files with a warning) and `fixable` (the values `--fix` would replace). A run that fails on its findings has `failure.code` `issues_found`.

### Fixing typos: `--fix`

`--fix` applies the fixes whose `safe` is `true` (see [Diagnostic fields](#diagnostic-fields)), such as `clear` for `tlp: Clear` or `Data Breach` for `Data-Breach`, and never one whose `safe` is `false`: `clear` for `clearr`, an ATT&CK id, a reference (`invalid_ref`). A person or an agent decides those. When a run finds safe fixes, its outcome line counts them (`2 fixable with --fix`) and its next step is the same command with `--fix`, also in `next_actions`.

```bash
opentide validate --fix --dry-run
opentide validate --fix
```

`--fix --dry-run` prints the edits as a unified diff, then the findings no safe fix resolves, and writes nothing. The files are unchanged, so the run exits `1` while they have errors. With `tlp: Clear` in the tutorial rule:

```text output-of="opentide validate --fix --dry-run" exit=1 state=vocabulary-case
--- a/objects/rules/sentinel-kql-rule.yaml
+++ b/objects/rules/sentinel-kql-rule.yaml
@@ -5,7 +5,7 @@
   version: 1
   created: 2026-01-01
   modified: 2026-01-02
-  tlp: Clear
+  tlp: clear
   author: Tutorial Author
   organisation:
     uuid: 00000000-0000-4000-8000-000000000099
→ opentide validate --fix · apply 1 safe fix
```

`--fix` writes the safe fixes, validates again and prints a `fixed:` line per value, then the findings that are left. Only the replaced value changes in each file: comments, quoting, key order, indentation and line endings stay as they were. Each edit is checked against the file as it is now, not as validation read it. The text it replaces must still be one the fix is safe for, so a value you saved over the typo in the meantime is kept. The file must still parse and differ in that value alone. Otherwise the edit is left out and its finding stays. Each file is written to a temporary file beside it and moved into place, so a write that fails (a full disk, a quota) leaves the original whole. A file that changed between the check and the write is left alone, with a warning. A second run has nothing to apply. The outcome line says what it fixed and what is left:

```text illustrative
fixed: objects/rules/sentinel-kql-rule.yaml:8:8 'Clear' → 'clear'
fixed: objects/threats/simulated-actor.yaml:9:8 'Clear' → 'clear'

error[invalid_ref]: Unknown objective or signal reference '00000000-0000-4000-8002-DEADBEEF0000'
   ╭─▶ objects/rules/sentinel-kql-rule.yaml:17:18
   │
16 │ techniques: [T1059]
17 │ detection_model: 00000000-0000-4000-8002-DEADBEEF0000   # the objective from step 4
   │                  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ no object has this id
   │
   ╰─ help: opentide info objectives lists the ones that exist

✗ 1 error in 1 file · fixed 2 values in 2 files · 3 objects checked · 1.8s
```

The sample is illustrative because it carries the run time. When nothing is left, the line is `✓ Fixed 2 values in 2 files · 3 objects valid · 1.8s` and the run exits `0`. When a file cannot be written, a `warning:` line names it and the outcome line says `could not write 1 fix`. `--fix` honours `--file`, `--uuid`, `--type` and `--check`: it fixes what that run found.

With `--json` the document is the second run's, so `report` holds what is left, and it gains `fixed` and `summary.fixed`:

```bash
opentide --json validate --fix
```

```json output-of="opentide --json validate --fix" state=vocabulary-case
{
  "fixed": [
    {
      "path": "objects/rules/sentinel-kql-rule.yaml",
      "line": 8,
      "code": "vocab_unknown",
      "before": "Clear",
      "after": "clear"
    }
  ],
  "ok": true,
  "summary": { "objects": 3, "errors": 0, "fixable": 0, "fixed": 1 }
}
```

Under `--dry-run` the document is the first run's, with `would_fix` (the same entries) and `diff` (the text above) instead of `fixed`.

### Watching: `--watch`

```bash
opentide validate --watch
```

`--watch` validates once, then looks at the modification times of the object files every 0.5 seconds and validates again after a save. A save that keeps the UUIDs in the file re-checks that file alone. Every object is re-checked instead, since other objects' findings may change with it, when a file is added or removed, when a UUID or reference in it changes, and when its object enters or leaves the catalogue: the file stops or starts parsing, or loses its `uuid`. Each run reports the whole workspace, findings from files it did not re-check included.

In a terminal the findings and the outcome line are redrawn in place, with a footer naming the file it re-checked and how to stop. In plain output (a pipe, `NO_COLOR`, `TERM=dumb`, CI) each run prints the findings it produced and one outcome line, and nothing is redrawn. Ctrl-C stops it with exit `0`. `--watch` honours `--file`, `--uuid`, `--type`, `--check` and `--strict`; with a narrowed scope every run re-checks that scope. It cannot be combined with `--fix` or `--format` (exit `2`, `failure.code` `usage_error`).

`--watch` never ends, so it is refused where nobody watches: under `--json`, a coding agent or `OPENTIDE_OUTPUT=agent`. It exits `2` at once with `failure.code` `usage_watch_needs_tty`, and the next step is `opentide validate`.

Filename conventions and recommended metadata are **not** schema errors — use [`opentide lint`](./lint.md).

### One JSON shape for every invocation

`--json` emits the same document whichever way you invoke validation. The full
report is always under `report`, and `checks` always maps a check name to that
check's verdict. Passing `--check` narrows `checks` to the one check you asked
for and adds `check` naming it; it does **not** move the report.

```bash
opentide --json validate --check schema
```

```json output-of="opentide --json validate --check schema"
{
  "checks": {
    "schema": { "check": "schema", "status": "passed" }
  },
  "report": {
    "ok": true,
    "issues": []
  },
  "check": "schema",
  "workspace": "...",
  "ok": true,
  "status": "passed"
}
```

So one expression reads the issue list regardless of invocation:

```bash
opentide --json validate                  | jq '.report.issues'
opentide --json validate --check schema   | jq '.report.issues'
```

!!! warning "Changed in 0.13.0"

    `--check` previously returned a different document from a bare `validate`:
    the report was placed under `issues` (so the list was at `issues.issues`)
    and a legacy `errors` map, keyed by UUID, was emitted alongside it. Neither
    appeared on a bare run, so a consumer could not parse both the same way.
    Both paths now emit the shape above. Read `report.issues` instead of
    `issues.issues`, and replace `errors` with `report.issues`, which carries
    the same failures with their field paths, codes and line numbers.

### Which workspace was checked

Run from anywhere inside the detection workspace: the CLI walks up to it (see [Repository root resolution](./global-options.md#repository-root-resolution)). The JSON payload names the directory it read objects from under `workspace`.

An empty catalogue is not an error. A full run that checked no objects still passes with exit `0`, `--strict` included, but says where it looked:

```text illustrative
✓ Validation passed, but no detection objects were found under ./
```

The directory is relative to the one you run in (`./`, `./detections`, `../`), or absolute when it is elsewhere.

If that path is not your workspace, `cd` into it or pass `--repo`.

### Files in subfolders

An object is a `.yaml` or `.yml` file placed directly in its folder (`objects/rules/rule.yaml`). A file in a subfolder (`objects/rules/team-a/rule.yaml`) is not an object: `validate` does not index or check it, and neither do `share`, `lint`, `deploy`, docs or exports. `validate` reports each such file once as a `nested_object_file` warning at its path:

```text illustrative
objects/rules/team-a/rule.yaml is in a subfolder of objects/rules and is not an object instance: it is not indexed, validated, shared, documented or deployed (opentide reads only files directly in objects/rules; see https://github.com/opentidehq/opentide/issues/584)
```

Move the file up into its object folder to make it an object. `--strict` fails on this warning. Through 0.17.2 `validate`, `share`, `lint`, docs and exports read subfolders too, while `deploy` skipped them.

### Selecting a file

`--file` matches like this:

| Target | Matches |
|--------|---------|
| Repo-relative path (`objects/rules/rule.yaml`, `./objects/rules/rule.yaml`) | That file only. It is resolved from the working directory and from the repository root, so it also works from outside the repo or with `--repo`. |
| Absolute path | That file only. |
| Bare file name (`rule.yaml`) | Every object file with that name, in any object folder. |

A path never falls back to its file name, and a path that names no object file fails with `scope_no_match`. A path to a file in a subfolder names no object: it fails with `scope_no_match` and the file's `nested_object_file` warning.

Every `--file` target must select at least one object. A target that matches nothing fails the run with a `scope_no_match` issue naming that target (`context.targets`), even when the other targets matched and validated cleanly. Through 0.14.2 the run failed only when no target matched at all, so a mistyped or quoted path beside a valid one passed without being validated.

Every issue reports the `file_path` of the object it concerns, so issues from two files that share a name stay apart when a bare file name selects both.

### Unparseable object files

An object file that is not valid YAML is reported as a `yaml_parse` issue against that path (exit `1`, and a complete report in `--json` mode) instead of raising a parser traceback. The message and the frame name the line and column where the parser stopped, and a note says what it was reading and where that started (`while parsing a flow sequence that starts at line 8, column 8`). It is reported once: `validate` does not also log it. The file is not indexed, so no other check can see it — the issue is emitted regardless of `--check`.

### Schema identifier

The `schema` check validates each object against the revision its `metadata.schema` names, so `rule::1.0` and `rule::1.1` rules validate side by side. An object without `metadata.schema` fails with `schema_missing` at that field. An identifier that is not registered, or that names another object type (a rule declaring `threat::1.0`), fails with `schema_validation` at that field. Neither case is checked against the newest revision instead. Through 0.15.0 an object without `metadata.schema` was checked against the newest revision of its type, and a rule declaring another type's identifier was checked as that type.

### Vendor rule ids

`rule_id`, `rule_id_bundle` and `rule_id::<tenant>` are not keys of any platform block. A rule that still carries one fails the `schema` check with `external_id_in_rule` at that field. Vendor ids belong in [deployment state](../usage/concepts/deployment-state.md); move them with [`opentide deploy migrate-state`](./deploy.md#deploy-migrate-state). A full-workspace run also checks every `*.json` under `.opentide/states/deployment/`, including orphan shards whose rule was deleted, and fails each unusable one with its `deployment_state_*` code (a non-canonical file name, a second file for the same rule, or a tenant key with surrounding spaces included). A run narrowed with `--file`, `--uuid` or `--type` checks the shards of the selected rules only. A rule without a shard is fine.

### Platforms this workspace has not enabled

A rule may carry a block for a platform this workspace has not enabled, for example a rule imported from a repository that deploys to Splunk. The block is still validated against that platform's model: an empty `query`, an unknown key, or a missing required field fails, and so does a key that is not a platform (`configurations.splnk`). A well-formed block passes with one `platform_not_enabled` warning per disabled platform, at `configurations.<platform>`:

```text illustrative
warning[platform_not_enabled]: this block will not deploy while splunk is disabled in this workspace; enable splunk with 'opentide setup platforms --splunk'
   ╭─▶ objects/rules/imported.yaml:24:3
   │
23 │ configurations:
24 │   splunk:
   │   ━━━━━━
   │

✓ 3 objects valid · 1 warning · 0.9s
```

In `--json` mode a line naming it is in `warnings`, and the structured finding (with `context.platform`) is in `report.warnings`. The warning does not fail `--strict`, which the generated commit hook and CI run, so an imported rule can be committed before its platform is enabled. [Deploy](./deploy.md) and live `validate query` skip a disabled platform until `opentide setup platforms` enables it, whatever the block's own `enabled` says.

### CVE check

`opentide validate --check cve` looks up each `threat.cve` identifier on [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu) (`GET /api/vulnerability/{id}`). Unknown IDs (empty JSON body) fail the check. Links in generated docs use the same aggregator: `https://vulnerability.circl.lu/vuln/{id}`.

Accepted identifiers:

- CVE (`CVE-2024-3094`)
- GitHub Security Advisories (`GHSA-rxwq-x6h5-x525`)
- GCVE, including GNA 0 which maps to CVE (`GCVE-0-2024-3094` is stored as `CVE-2024-3094`)

The check no longer scrapes NVD through `mitrecve`. If Vulnerability-Lookup is unreachable, those identifiers are skipped (logged) rather than reported as invalid.

### Queries

```bash
opentide validate
opentide validate --queries warn
opentide validate --queries off
opentide validate --check queries --file objects/rules/example.yaml
```

The `queries` check is one of the default checks. It reads every query the selected objects carry (each platform block's `query`, and hunts) and checks it offline with the analysis engine, in its own language: the check [`validate query`](#offline-the-analysis-engine) runs, inside `validate`. `--check queries` runs it alone. It honours `--file`, `--uuid`, `--type`, `--strict`, `--watch` and `--fix` (no query finding has a safe fix).

It reports the engine's errors: a query the platform would reject (`kql_parse_error`, `spl_unknown_command`, `esql_unavailable`, ...). They join `report.issues` at their place in the file and print as code frames with the rest; `context` names the `language`, the `platform` and the engine's `position`. The engine's warnings and notes (slow query shapes, deprecated commands) are style, which [`opentide lint`](./lint.md#queries) reports. `summary.queries` counts the queries checked, and the outcome line says it: `✓ 6 objects valid · 4 queries · 1.2s`.

`--queries` sets how a rejected query is reported:

| `--queries` | A rejected query | The run |
|-------------|------------------|---------|
| `error` (default) | An error in `report.issues` | Fails (exit `1`) |
| `warn` | A warning in `report.warnings`, with `context.reported_as_warning` and a frame note | Passes, unless `--strict` |
| `off` | Not checked: `checks` and `summary` have no `queries` entry | The other checks decide |

`warn` is for a catalogue that has to keep validating while its queries are fixed; `off` validates everything but the queries. `--queries` with `--check` other than `queries` exits `2`, as does `--check queries --queries off`: the run would ignore the one or contradict the other. A failed run's `validate · check again` step keeps the mode.

A query `opentide new` wrote as a placeholder (`...`, marked `# opentide:placeholder`) is an error too, since no platform accepts it; its frame says so and its help asks for the rule's query.

When the engine does not load, the check reports one `engine_unavailable` error and the run fails, whatever `--queries` says but `off`: the check never skips. The engine ships with `pip install opentide`; there is no extra to install.

### Default checks

When no `--check` is specified, the pipeline runs:

- `id-uniqueness`
- `uuid-format`
- `schema` (includes vocabulary and cross-object references)
- `configuration` (the merged files under `.opentide/configurations/`, against their models)
- `queries` (every query, offline, with the analysis engine; `--queries off` leaves it out)

CVE lookup is **opt-in**: pass `--check cve`. It is not part of the default CLI pipeline so offline `opentide validate` stays deterministic.

## Query validation

```bash
opentide validate query
opentide validate query --platform splunk --changed
opentide validate query --file objects/rules/example.yaml --queries warn
opentide validate query --file hunting/lsass.kql
opentide validate query --platform sentinel --live
opentide validate query --platform splunk --live --changed
opentide validate query --platform splunk --live --file objects/rules/example.yaml
opentide validate query --platform splunk --live --strategy RELEASE --wide
```

`validate query` checks queries in two ways. **Offline**, the default, the analysis engine that ships with opentide parses each query in its platform's language: no tenant, no credentials, no network. It is the `queries` check of `opentide validate`, on its own, with a query file allowed. **`--live`** sends one platform's rule queries to its tenants.

| Flag | Purpose |
|------|---------|
| `--platform` | The platform whose queries to check. Offline, default: every platform the engine parses. Required with `--live` (exit `2`, `failure.argument` `--platform`, without it) |
| `--live` | Check the queries on the platform's tenants (needs credentials) |
| `--changed` | Check only the rule files this run changed: the pull or merge request, the push, or outside CI the last commit (see [Which rules are checked](#which-rules-are-checked)) |
| `--file` | Check only this rule file: a path or a bare file name, matched as in [object validation](#selecting-a-file). A file with a query extension (`.kql`, `.spl`, `.esql`, `.eql`, `.kuery`, `.lucene`) is one query in that language, checked offline. Repeatable |
| `--uuid` | Check only the rule with this UUID. Repeatable |
| `--queries` | Offline: how a rejected query is reported, `error` (the default) or `warn`, as in [`validate`](#queries). `off` exits `2`: it would check nothing. Refused with `--live` |
| `--strict` | Offline: fail on warnings too (with `--queries warn`). Refused with `--live` |
| `--strategy` | `--live`: check only the rules a run with this strategy deploys, on the tenants that accept it: `PREVIEW` or `RELEASE`, repeatable. Default: both |
| `--wide` | `--live`: ignore each rule's status: check every status except `DISABLEMENT` and `DELETION`, `INERT` included |

`--strategy` and `--wide` choose tenants, so offline they exit `2` (`usage_error`); so do a query file with `--live`, which sends rule queries, and a query file with `--changed`. `--queries` and `--strict`, typed before `query`, carry over: `opentide validate --queries warn query` is `opentide validate query --queries warn`. Through 0.18.0 a bare `validate query` refused and named `--live`; it now runs the offline check.

### Offline: the analysis engine

The engine is [opentidehq/language-server](https://github.com/opentidehq/language-server), compiled into the opentide package that `pip install opentide` installs; there is no extra and no second package. It reads every rule file directly in the rules folder, or those `--changed`, `--file` and `--uuid` select, and checks every query of the platform's block, whatever the rule's status or whether the platform is enabled:

| Platform | Language and profile |
|----------|----------------------|
| `sentinel` | KQL, Sentinel tables |
| `defender_for_endpoint` | KQL, Defender tables |
| `splunk` | SPL |
| `elastic` | ES\|QL, EQL, Kibana KQL or Lucene, by the block's `type` and `language`; ES\|QL against the lowest `setup.version` of the block's tenants |
| `carbon_black_cloud` | Lucene, Carbon Black dialect |

SentinelOne's S1QL has no offline parser: `--platform sentinel_one` exits `2` (`failure.code` `usage_missing_option`, `failure.argument` `--live`) and names `--live`. CrowdStrike and HarfangLab are never validated (see [Supported platforms](#supported-platforms)).

```bash
opentide --json validate query --platform sentinel_one
```

```json output-of="opentide --json validate query --platform sentinel_one" exit=2
{
  "platform": "sentinel_one",
  "mode": "offline",
  "supported": true,
  "ok": false,
  "status": "failed",
  "message": "sentinel_one queries are checked on the tenant only; the offline engine does not parse them. Re-run with --live."
}
```

Each finding prints as a code frame at its place in the rule file, with the query coloured as your editor colours it when you run it at a terminal, then one outcome line. A rule file that is not UTF-8 or not YAML is an error (`yaml_parse`), never a file silently passed over. A finding's code (`kql_unknown_table`, `spl_parse_error`, `esql_unavailable`, ...) has an `opentide explain` page and its help line links the language's reference. The sample is illustrative, because it needs a rule with a broken query:

```text illustrative
error[kql_unknown_operator]: unknown tabular operator 'wher'
   ╭─▶ objects/rules/sentinel-kql-rule.yaml:31:23
   │
30 │     query: |
31 │       SecurityEvent | wher EventID == 4688
   │                       ━━━━━━━━━━━━━━━━━━━━
   │
   ╰─ help: did you mean 'where'?

✗ 1 error in 1 file · 3 queries checked
→ opentide explain kql_unknown_operator · how to fix it
→ opentide validate query · check again
```

It reports the engine's errors, as `validate` does: they fail the run with exit `1` (`failure.code` `issues_found`), or, with `--queries warn`, print as warnings and exit `0` unless `--strict`. The engine's warnings and notes, such as a slow query shape (`kql_where_not_first`, `spl_wildcard`), are style: [`opentide lint`](./lint.md#queries) reports them. A passing run ends `✓ 3 queries valid`; one under `--queries warn` with rejected queries `! 2 warnings in 1 file · 3 queries checked`. With no query to check, the result is `skipped` with exit `0`. When the engine does not load, the run fails with exit `1` and `failure.code` `engine_unavailable`: it never skips.

A query file (`--file hunting/lsass.kql`) holds one query in the language its extension names, in any case (`.KQL` too). With `--platform` it is checked with that platform's profile (`--platform defender_for_endpoint` knows Defender's tables) and `platform` names it; without, with the language alone, and `platform` is empty. `field_path` is empty for it, and given alone it checks no rule. A query file that does not exist, or whose language the `--platform` does not use (a `.kql` file with `--platform splunk`), exits `2`; one that is not UTF-8 or holds no query fails with exit `1`.

`--json` reports `mode` `offline`, `queries_validated`, one entry per query under `queries` (`path`, `platform`, `language`, `field_path`, `line`, `column`, `errors`), every finding under `diagnostics` with the [diagnostic fields](#diagnostic-fields), `engine` (the engine version), and `summary` (`queries`, `files`, `errors`, `warnings`, `notes`, `error_files`, `warning_files`).

`opentide validate` checks the queries together with the objects. Your editor shows the engine's findings as you type: see [`opentide lsp`](./lsp.md).

### `--live`

`--live` builds the platform client and submits the catalogue queries, so it needs
tenant credentials. The vendor SDKs ship with `pip install opentide`; there are no
extras. If an SDK will not import, the environment is damaged and the command
fails with the remedy rather than a `ModuleNotFoundError` traceback: the `advice`
field in `--json`, a `help: reinstall opentide: pip install --force-reinstall
opentide` line under the `error:` line otherwise.
Only the requested platform's engine is
loaded — validating Sentinel never imports the CrowdStrike or HarfangLab
modules. A platform with no `[[tenants]]` entry fails the same way, before the
client is built, and names the file to edit.

A tenant the check cannot reach (a refused connection, a DNS or TLS failure, a
timeout, or a proxy that will not connect) fails the check with exit `1`, not a
traceback. On Splunk, SentinelOne, Elastic, Carbon Black Cloud and Defender for
Endpoint, `--json` names the `tenant` and the `host` that failed, and `message`
carries the network error; Sentinel reports it in its own failed result. The human output prints the same message as an `error:` line,
with the `advice` as a `help:` line under it. The platform's remaining tenants are not checked after the
first one that cannot be reached. The sample is illustrative, because it needs a
configured tenant:

```json illustrative
{
  "platform": "splunk",
  "mode": "live",
  "supported": true,
  "tenant": "Production",
  "host": "splunk.example.com:8089",
  "advice": "check the 'Production' tenant in .opentide/configurations/platforms/splunk.toml and the network path to splunk.example.com:8089; behind a proxy, pass opentide --proxy",
  "ok": false,
  "status": "failed",
  "message": "Cannot reach splunk tenant 'Production' at splunk.example.com:8089: <urlopen error [Errno 111] Connection refused>"
}
```

### Which rules are checked

A live check sends each rule's query to the tenants a deploy would send the rule to. By default it reads every rule file directly in the rules folder, and checks each rule whose status maps to a strategy a `PREVIEW` or `RELEASE` run deploys: `PREVIEW`, `RELEASE` and `UNIVERSAL`. Rules whose status maps to `DISABLEMENT` or `DELETION` send no query: they are disabled or deleted, not deployed active. `--wide` drops the strategy filter, so `INERT` rules are checked too, on every tenant accepting the run's strategies.

`--strategy PREVIEW` or `--strategy RELEASE` narrows the check to the rules that run deploys, on the tenants that accept it. See [Statuses, strategies and tenants](../usage/concepts/statuses-and-strategies.md).

Three flags narrow the rule files and leave the rest alone:

- `--changed` reads the rule files a deploy of the same run reads. On a pull or merge request: the diff from the request's merge base. On any other GitHub Actions, GitLab CI or Azure Pipelines run: the pushed commit's diff. Outside CI: the last commit. The [generated pipelines](../usage/workflows/ci-cd.md) pass `--changed`, so a pull request that edits one rule sends that rule's queries, not the whole catalogue's. A changed rule in `PRODUCTION` status is checked on the pull request, on the tenants that accept `RELEASE`, before it merges. When no changed rule has a block for the platform, the result is `skipped` with exit `0`.
- `--file` and `--uuid` select rules by file or UUID. Each target must select a rule file directly in the rules folder. A target that selects none fails the run with exit `1` before any query is sent, and `--json` lists it under `unmatched`. `--changed` cannot be combined with either (exit `2`).

`--json` names the narrowing in `scope`: `changed` or `selected`.

Through 0.16.1 the generated pipelines passed none of these flags, so every run sent every rule's queries: on a catalogue of a few hundred Splunk rules, the check took most of an hour.

### Which tenants are checked

A rule is checked on the tenants a deploy sends it to: those whose `strategies` accept a run strategy that deploys the strategy its status maps to. A rule in `DEVELOPMENT` (`PREVIEW`) is checked on the tenants accepting `PREVIEW`; one in `PRODUCTION` (`RELEASE`) on those accepting `RELEASE`. A `manual` tenant is checked only for the rules that list it under `tenants`, and a rule's `tenants` list limits it to those tenants.

When an explicit `--strategy` leaves every rule without a tenant (for example, only `PREVIEW` rules under `--strategy RELEASE`), nothing needed checking: the result is `skipped` with exit `0`. Exit `2` is kept for rules that reach no configured tenant at all, where the check could never run.

Through 0.16.1 a live check without `--plan` reached every tenant a rule could reach, whatever the tenant's `deployment` class. Since 0.17.0 it follows deploy: a `PREVIEW` rule is not checked on a tenant that only accepts `RELEASE`. The pull request that moves the rule to a `RELEASE` status checks it there, before that change merges.

A passing run ends with `✓ 4 queries valid on 2 tenants`; a failing one with `error: Queries rejected on sentinel · 4 checked on 2 tenants`, below the rejections the validator logged. `--json` reports the run's strategies and how many queries each tenant received, and the totals in `summary`. The sample is illustrative, because a live run needs tenant credentials:

```json illustrative
{
  "platform": "sentinel",
  "mode": "live",
  "status": "passed",
  "message": "4 queries valid on 2 tenants",
  "strategies": ["PREVIEW", "RELEASE"],
  "queries_validated": 4,
  "queries_per_tenant": { "Staging": 2, "Production": 2 },
  "summary": { "queries": 4, "tenants": 2 }
}
```

A run that sends no query never reports `passed`. When there are rules for
the platform but none of them resolves to a configured tenant, the command
reports `skipped`, names the reason in `message` and `advice`, and exits `2`,
the same code the generated CI credential guard uses for a check that did not
run. Through 0.14.2 that case printed `Query validation passed` with zero
queries sent, which made the generated pipeline's live gate a no-op. With no
rules for the platform at all, the result is still `skipped` with exit `0`:
there is nothing to check.

`--plan` and `DEPLOYMENT_PLAN` were removed in 0.17.0; either fails with exit `2` and names the `--strategy` to use.

### Supported platforms

Live query validation works on **six platforms**; the offline engine on five of them:

| Platform | `--live` | Offline |
|----------|:--------:|:-------:|
| `sentinel` (KQL) | ✅ | ✅ |
| `defender_for_endpoint` (KQL) | ✅ | ✅ |
| `elastic` (Kuery, Lucene, EQL, ES\|QL) | ✅ | ✅ |
| `splunk` (SPL) | ✅ | ✅ |
| `sentinel_one` (S1QL) | ✅ | ❌ |
| `carbon_black_cloud` (Lucene) | ✅ | ✅ |

### Elastic live validation and deploy

`opentide validate query --platform elastic --live` checks each rule against the tenant. It does not parse Kuery, Lucene, EQL, or ES|QL in-process.

- It emits configuration advisories as warnings. Each carries the stable code of the Elastic platform specification (`code` in the log record, which is also its event name), the same code the language server shows in the editor:

  | Code | Raised when |
  |------|-------------|
  | `lookback_zero` | `scheduling.lookback` is `0` (`0m`, `0s`, `PT0S`) |
  | `lookback_long` | `scheduling.lookback` exceeds `1h`. It is additional overlap added to `interval`, not the total window |
  | `threshold_lookback` | A `threshold` rule has `scheduling.lookback` above `scheduling.interval` |
  | `esql_metadata_id` | A non-aggregating ES\|QL query (no `STATS` step; `INLINE STATS` keeps rows) has no `METADATA _id`. Comments and strings do not count |
  | `risk_band` | An explicit `risk` score falls outside the RFC 0007 band for the rule's severity (`low` `0–21`, `medium` `22–47`, `high` `48–73`, `critical` `74–100`) |
  | `eql_maxspan_window` | An EQL `sequence` `maxspan` (`ms`, `s`, `m`, `h` or `d`, read from the `sequence` header) exceeds `scheduling.interval + scheduling.lookback` |
  | `eql_maxspan_lookback` | The `maxspan` fits that window but exceeds `scheduling.lookback`. A sequence gets one of the two EQL codes, never both |
  | `technique_not_enterprise` | The rule references a non-Enterprise (Mobile or ICS) ATT&CK technique, which is left out of the compiled `threat` |

  The three look-back codes are independent, so a threshold rule with a look-back over `1h` raises `lookback_long` and `threshold_lookback`. Each log record also carries `legacy_event`, the event name the code replaced (`elastic_lookback_zero_warning`, `elastic_lookback_long_warning`, `elastic_esql_metadata_id_warning`, `elastic_risk_score_band_warning`, `elastic_eql_maxspan_window_warning`, `skipping_non_enterprise_technique`). It is removed in the release after next. The tenant `setup.suppression = false` with a rule that configures `suppression` is a separate warning, `suppression_omitted_basic_license`.
- It runs the Elasticsearch and Kibana checks below.
- It posts the compiled rule to Kibana `rules/preview` with `invocationCount: 1` and a UTC `timeframeEnd`. Entries in `logs[].errors` fail the rule. `logs[].warnings`, including a missing index, are warnings. HTTP 400 is a schema error, and any other non-200 response fails that rule. HTTP 401 or 403, or a missing preview-index privilege, fails that tenant and the remaining rules on it are skipped.

The same Elasticsearch and Kibana checks run before every `opentide deploy` to Elastic, against `elasticsearch_url` and Kibana with the tenant API key:

- ES|QL is sent to `POST _query` with `| LIMIT 0` appended. A `parsing_exception` fails the rule, including a query Kibana would still accept on create (for example `WHER`). On `verification_exception`, the `FROM` sources (not a trailing `METADATA` clause) are resolved. An empty resolution deploys with a warning; a resolution that finds indices fails the rule.
- When `data_view_id` is set, `GET /api/data_views/data_view/{id}` resolves its index pattern. A data view that cannot be read (for example `404`) fails the rule: `data_view_id` must name an existing data view, and opentide never creates one.
- Aggregation fields (`suppression.group_by`, `threshold.field`, `threshold.cardinality.field`, `new_terms.fields`) are checked with `_field_caps`. Each field must exist and be aggregatable, and a `_field_caps` call that fails fails the rule. For ES|QL, `group_by` must be one of the pre-flight columns. Empty indices deploy with a warning. A rule with no explicit source skips the check with a warning.
- Custom timestamp fields (`overrides.timestamp`, `eql.timestamp_field`) are checked with `_field_caps`. Missing indices or fields not yet mapped emit a warning; a failed `_field_caps` call or a field mapped with a non-date type (anything other than `date` or `date_nanos`) fails the rule.
- Indicator match (`threat_match`) mapping fields (`threat.mapping`) are checked against `threat.index` and the rule's event sources via `_field_caps`. Unonboarded indices or fields not yet mapped emit a warning; a failed `_field_caps` call or a field mapped with a non-searchable type fails the rule.

A rule that fails is not created or updated, and the command exits `1`. Later rules are still checked. An index pattern that matches nothing still deploys, with a warning.

CrowdStrike (correlation filter) and HarfangLab (Sigma or YARA) return unsupported — never fake validation. The fields on each `configurations` block, required and optional, are the [platform specs](/docs/specifications/specs/platforms/). [Platforms](../usage/concepts/platforms.md#platform-block-schemas) links each one.

The result is a normal failure envelope, so `--json` shape does not change between
supported and unsupported platforms:

```bash
opentide --json validate query --platform crowdstrike
```

```json output-of="opentide --json validate query --platform crowdstrike" exit=1
{
  "platform": "crowdstrike",
  "valid": null,
  "supported": false,
  "ok": false,
  "status": "failed",
  "message": "query validation not supported for crowdstrike"
}
```

The process exits `1`.

## SDK equivalent

```python
from opentide.validation.session import run_validation
from opentide.validation.scope import ValidationScope

report = run_validation(scope=ValidationScope.full())
print(report.ok, len(report.errors))
```

See [SDK validation](../sdk/validation.md).

## Source

`src/opentide/cli/commands/validate.py`, `src/opentide/cli/services/validation.py`
