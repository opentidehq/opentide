---
title: opentide lint
description: Catalogue hygiene — filename slugs, recommended metadata, placeholders and query style, distinct from validation.
---

# opentide lint

Convention and style checks that `opentide validate` does not cover: is the catalogue clean? `validate` decides whether it deploys. Lint does **not** replace `--strict` schema/graph validation.

```bash
opentide lint
opentide lint --check filenames
opentide lint --check queries
opentide lint --fix
opentide lint --strict
```

## Checks

| `--check` | What it does | `--fix` |
|----------|----------------|---------|
| `filenames` | Object YAML stem must equal `slugify(name)` | Renames files. On a collision in the same folder, appends `{uuid[:8]}` |
| `metadata` | Reports each `metadata` key in [`required`](#configuration) that is missing or empty. By default `author` and `organisation` | Not auto-fixed |
| `placeholders` | Reports each value [`opentide new`](./new.md) filled in for you, marked `# opentide:placeholder` | Not auto-fixed |
| `queries` | Reports the analysis engine's warnings and notes on each query (slow shapes, deprecated commands) and Elastic block settings (see [Queries](#queries)) | Not auto-fixed |

Default (no `--check`) runs every check that [`lint.toml`](#configuration) leaves enabled, which out of the box is all four. YAML formatting and orphan doc pages are not in this command yet. Vocabulary pins ship inside opentide, so lint does not check them: opentide's own CI checks the bundled pins against the specifications whenever they change.

Lint reads the `.yaml` and `.yml` files directly in `objects/{threats,objectives,rules}/` and does not rebuild the object registry. A file in a subfolder is not an object: the `filenames` check reports it once as a `warning` with `code: nested_object_file` and checks nothing else in it.

## Flags

| Flag | Purpose |
|------|---------|
| `--check` | Repeatable. `filenames`, `metadata`, `placeholders` or `queries`. Runs only the named checks, including one `lint.toml` disables |
| `--fix` | Apply safe filename renames |
| `--strict` | Exit `1` when any finding exists (CI gate). Default is report-only |
| `--format` | `text` (code frames, the default), `sarif` or `codequality`: the findings as a SARIF 2.1.0 or GitLab Code Quality report, as for [`validate`](./validate.md#reports-and-ci-annotations) |
| `--output` | Write the `--format` report to this file and still print the code frames. Without it the report is all of stdout. Required with `--json`. Needs `--format sarif` or `codequality`: with `text` it exits `2` |

`--fix` is idempotent.

In a GitHub Actions or Azure Pipelines job each finding is also an annotation on stdout, and the outcome line and the findings go to the job summary, as for [`validate`](./validate.md#reports-and-ci-annotations). A `note` finding (an `info` severity) is a GitHub notice and is not sent to Azure, which has no such level.

## Output

Human output prints each finding as a code frame, like [`validate`](./validate.md), then one line counting them. The [tutorial](../usage/tutorial.md) catalogue passes every check:

```text output-of="opentide lint"
✓ 3 files clean
```

A finding prints `severity[code]: message` (an `info` finding prints as `note`), the path with `:line:column` when it points at a key, and that line of the file. This is the shape, from a threat whose file was not renamed to its slug and whose recommended metadata is empty:

```text illustrative
warning[filename_mismatch]: Filename 'Simulated Actor.yaml' does not match slugify(name)='simulated-actor'
  ╭─▶ objects/threats/Simulated Actor.yaml
  ╰─ help: rename it to objects/threats/simulated-actor.yaml

note[metadata_recommended]: Recommended metadata missing: author, organisation
  ╭─▶ objects/threats/Simulated Actor.yaml:2:1
  │
1 │ name: Simulated Actor
2 │ metadata:
  │ ━━━━━━━━
  │
  ╰─ help: add the missing keys under metadata

! 2 findings in 1 file · 1 warning, 1 note
→ opentide lint --fix · rename 1 file to match their names
```

When more than one severity is left, the count splits them. Notes alone are no warning: the line counts them as notes and takes `✓` (`✓ 6 notes in 6 files`), while the JSON `status` stays `issues`. When a filename finding can be fixed by renaming, the count is followed by the command that does it. A file renamed by `--fix` gets `note: renamed from <old path>`; the count leaves it out and ends with `· 1 fixed`, so a run whose findings were all fixed prints `✓ 3 files clean · 1 fixed`. Under `--strict`, findings fail the run: the count prints as `✗ 2 findings in 1 file` and `failure.code` is `issues_found`. A workspace with no object files passes, and says where it looked.

### JSON findings

`--json` returns the same findings under `findings`, with `count` and `fixed` totals. Every finding has these keys:

| Key | Value |
|-----|-------|
| `check` | `filenames`, `metadata`, `placeholders` or `queries` |
| `severity` | `error`, `warning` or `info` (table below) |
| `path` | Object file, relative to the workspace |
| `yaml_line` | Zero-based line of the key the finding is about, like `yaml_line` in `validate`. `null` when the finding is about the whole file, or the key comes from a `<<:` merge and has no line of its own |
| `uuid` | The object's `metadata.uuid`. `null` when the file did not parse or has no UUID |
| `message` | What is wrong |
| `code` | `filename_mismatch`, `name_missing`, `metadata_recommended`, `placeholder`, `yaml_parse`, or the engine's code for a `queries` finding (`kql_where_not_first`, `spl_wildcard`, `lookback_zero`, ...). `opentide explain <code>` describes it |
| `field_path` | The key the finding is about (`["metadata"]`, `["configurations", "sentinel", "query"]`), or `[]` |
| `line`, `column`, `end_column` | One-based position of that key, of the YAML error, or of the engine's finding in the query. `null` when unknown |
| `help` | What to do, or `null` |
| `fix` | Always `null`: a rename is not a text edit. `opentide lint --fix` renames |
| `explain` | `opentide explain <code>` |

`summary` counts the object `files` read, the `findings` and the `fixed` ones.

A placeholder's `help` is the step that clears it. A filename mismatch adds `expected`, the path the file should have. Under `--fix` it also has `fixed`, and `from` (the old path) when the file was renamed. `fixed` is `false` when a file already exists at `expected`.

| Finding | `severity` | `yaml_line` |
|---------|------------|-------------|
| Object YAML does not parse, or is not a mapping | `error` | `null` |
| Object has no `name` | `error` | The `name:` key when it is present but empty or not a string, else `null` |
| Filename is not `slugify(name)` | `warning` | `null` |
| A `metadata.required` key missing or empty | `info` | The `metadata:` key, or `null` when there is no `metadata` block |
| A value marked `# opentide:placeholder` | `warning` | The marked line |
| An engine warning on a query or an Elastic block | `warning` | The finding's line |
| An engine note (a hint) on a query | `info` | The finding's line |

These are the defaults; a check's `severity` in `lint.toml` replaces them for every finding of that check. Severity is for sorting and triage only. `--strict` exits `1` on any finding, whatever its severity.

## Configuration

Lint reads `lint.toml` like any other [configuration file](../usage/configuration.md): opentide ships the defaults below, and `.opentide/configurations/lint.toml` in your workspace overrides the keys it sets. Without that file, lint behaves as it did before it was configurable.

```toml
# Bundled defaults
[filenames]
enabled = true

[metadata]
enabled = true
required = ["author", "organisation"]

[placeholders]
enabled = true

[queries]
enabled = true
```

| Key | Tables | Value |
|-----|--------|-------|
| `enabled` | `[filenames]`, `[metadata]`, `[placeholders]`, `[queries]` | `false` skips the check when no `--check` is given. `--check` wins: `opentide lint --check metadata` runs the metadata check even when it is disabled. The unparsable-file and missing-`name` findings belong to `filenames`, so disabling it drops them too (`validate` still reports both) |
| `severity` | `[filenames]`, `[metadata]`, `[placeholders]`, `[queries]` | `error`, `warning` or `info`. Replaces the severity of every finding the check reports, an unparsable file included |
| `required` | `[metadata]` | The `metadata` keys every object must fill. It replaces the default list rather than adding to it, and `[]` turns the metadata check into a no-op |

`required` takes any key a `metadata` block can hold: `uuid`, `schema`, `version`, `created`, `modified`, `tlp`, `author`, `contributors`, `organisation`, `reviewed`. A key counts as missing when it is absent, `null`, a blank string or an empty list; `organisation` needs a `name` (or the `organization` spelling). Each object is asked only for the keys its own schema accepts: `reviewed` exists on `rule::1.1` metadata alone, so it is never demanded of a threat, an objective or a `rule::1.0` rule, whose schemas reject it.

A workspace that wants authors but tracks organisations elsewhere, and treats a missing author as an error:

```toml
# .opentide/configurations/lint.toml
[metadata]
required = ["author"]
severity = "error"
```

A value lint cannot use fails the command with exit `2` and a message that names the key, before any object is read. That covers an unknown `required` field, an unknown table or key (a typo such as `requried`), a `severity` outside the three values, and an `enabled` that is not `true` or `false`. From a workspace whose `lint.toml` sets `required = ["owner"]`:

```text illustrative
FATAL: lint.toml [metadata].required: unknown metadata field(s) 'owner'. Known fields: uuid, schema, version, created, modified, tlp, author, contributors, organisation, reviewed
```

### Templates follow `required`

[`opentide generate templates`](./generate.md) writes each `required` key uncommented in the object templates and VS Code snippets, so a new object shows every key lint will ask for. Optional keys that lint does not require stay commented. With the defaults, a template's `metadata` block ends:

```yaml
  author:
  #contributors:
    #-
  organisation:
    uuid:
    name:
```

Fill those keys, or delete the block if you set `required` to leave it out: `organisation` left empty fails `validate`, which needs its `uuid` and `name`. Regenerate templates after changing `required`. [`opentide new`](./new.md) fills `author` and `organisation` from git and the catalogue, and comments out a key it has no value for, so the object it writes still validates.

### Placeholders

`opentide new` writes a valid object at once, so a required value nobody has chosen yet gets a stand-in: the first value the schema allows (an ATT&CK technique, a category) or `...` for free text. Each such line ends in `# opentide:placeholder`, and `lint` reports it as a `placeholder` warning. The message names the key, or the key and index for an item of a list (`mitre_attack[0]`), and the finding carries `line`, `column` and `end_column` (1-based, end exclusive) around the value, or around the key of a block scalar:

```text illustrative
warning[placeholder]: mitre_attack[0] holds a placeholder value written by opentide new
   ╭─▶ objects/threats/credential-dumping.yaml:30:7
   │
29 │   mitre_attack:
30 │     - T1548  # opentide:placeholder
   │       ━━━━━
   │
   ╰─ help: replace the value, then delete the '# opentide:placeholder' comment
```

Plain `lint` and `validate` still pass, so a draft can be committed (a placeholder query, `...`, is not sent to the analysis engine: neither `validate` nor the `queries` check reports it as a query): the commit hook runs `validate --strict` only. The CI pipeline from `opentide setup ci` also runs `lint --strict`, which fails until every marked value is replaced and its marker deleted. A placeholder looks like a real choice, so until then `generate` exports it like one (an ATT&CK technique in the coverage layer, for instance).

### Queries

The `queries` check runs the analysis engine that [`opentide validate`](./validate.md#queries) runs, and reports what `validate` leaves out: the engine's warnings and notes. A query the platform would reject is an error, and `validate`'s; what lint reports would deploy, but reads as a slow query shape (`kql_where_not_first`, `spl_wildcard`), a deprecated command, or an Elastic block setting that misses events (`lookback_zero`, `risk_band`). Each finding prints as the engine frames it, at its place in the rule file, with the query coloured at a terminal; its help links the language's reference, and `opentide explain <code>` describes it.

```text illustrative
warning[kql_where_not_first]: `where` is not the first operator after the table reference; filter before later operators
   ╭─▶ objects/rules/sentinel-kql-rule.yaml:33:9
   │
32 │       | summarize count() by Account
33 │       | where Account != ""
   │         ━━━━━━━━━━━━━━━━━━━
   │
   ╰─ help: the KQL reference: https://learn.microsoft.com/kusto/query/
```

A warning is `warning`, a note `info`; `[queries] severity` replaces both. A placeholder query is left to the `placeholders` check. When the engine does not load, lint fails with exit `1` and `failure.code` `engine_unavailable`, as `validate` does; `--check` without `queries` does not need it.

## Source

`src/opentide/cli/services/lint.py`
