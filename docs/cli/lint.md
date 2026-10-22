---
title: opentide lint
description: Catalogue hygiene — filename slugs and recommended metadata, distinct from schema validation.
---

# opentide lint

Convention checks that `opentide validate` does not cover. Lint does **not** replace `--strict` schema/graph validation.

```bash
opentide lint
opentide lint --check filenames
opentide lint --fix
opentide lint --strict
```

## Checks

| `--check` | What it does | `--fix` |
|----------|----------------|---------|
| `filenames` | Object YAML stem must equal `slugify(name)` | Renames files. On a collision in the same folder, appends `{uuid[:8]}` |
| `metadata` | Reports each `metadata` key in [`required`](#configuration) that is missing or empty. By default `author` and `organisation` | Not auto-fixed |

Default (no `--check`) runs every check that [`lint.toml`](#configuration) leaves enabled, which out of the box is both. YAML formatting and orphan doc pages are not in this command yet. Vocabulary pins ship inside opentide, so lint does not check them: opentide's own CI checks the bundled pins against the specifications whenever they change.

Lint walks `objects/{threats,objectives,rules}/**/*.yaml` and does not rebuild the object registry.

## Flags

| Flag | Purpose |
|------|---------|
| `--check` | Repeatable. `filenames` or `metadata`. Runs only the named checks, including one `lint.toml` disables |
| `--fix` | Apply safe filename renames |
| `--strict` | Exit `1` when any finding exists (CI gate). Default is report-only |

`--fix` is idempotent.

## Output

Human output prints one line per finding, then the summary. The [tutorial](../usage/tutorial.md) catalogue passes both checks:

```text output-of="opentide lint"
OK Catalogue lint passed
```

A file that fails them is printed as `[check/severity] path: message` before that summary, with `path:line` when the finding points at a key in the file (the line is one-based, as in `validate`). This is the shape, from a threat whose file was not renamed to its slug and whose recommended metadata is empty:

```text illustrative
[metadata/info] objects/threats/Simulated Actor.yaml:2: Recommended metadata missing: author, organisation
[filenames/warning] objects/threats/Simulated Actor.yaml: Filename 'Simulated Actor.yaml' does not match slugify(name)='simulated-actor'
ISSUES Catalogue lint found issues
```

A file renamed by `--fix` gets `(renamed from <old path>)`.

### JSON findings

`--json` returns the same findings under `findings`, with `count` and `fixed` totals. Every finding has these keys:

| Key | Value |
|-----|-------|
| `check` | `filenames` or `metadata` |
| `severity` | `error`, `warning` or `info` (table below) |
| `path` | Object file, relative to the workspace |
| `yaml_line` | Zero-based line of the key the finding is about, like `yaml_line` in `validate`. `null` when the finding is about the whole file, or the key comes from a `<<:` merge and has no line of its own |
| `uuid` | The object's `metadata.uuid`. `null` when the file did not parse or has no UUID |
| `message` | What is wrong |

A filename mismatch adds `expected`, the path the file should have. Under `--fix` it also has `fixed`, and `from` (the old path) when the file was renamed. `fixed` is `false` when a file already exists at `expected`.

| Finding | `severity` | `yaml_line` |
|---------|------------|-------------|
| Object YAML does not parse, or is not a mapping | `error` | `null` |
| Object has no `name` | `error` | The `name:` key when it is present but empty or not a string, else `null` |
| Filename is not `slugify(name)` | `warning` | `null` |
| A `metadata.required` key missing or empty | `info` | The `metadata:` key, or `null` when there is no `metadata` block |

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
```

| Key | Tables | Value |
|-----|--------|-------|
| `enabled` | `[filenames]`, `[metadata]` | `false` skips the check when no `--check` is given. `--check` wins: `opentide lint --check metadata` runs the metadata check even when it is disabled. The unparsable-file and missing-`name` findings belong to `filenames`, so disabling it drops them too (`validate` still reports both) |
| `severity` | `[filenames]`, `[metadata]` | `error`, `warning` or `info`. Replaces the severity of every finding the check reports, an unparsable file included |
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

Fill those keys, or delete the block if you set `required` to leave it out: `organisation` left empty fails `validate`, which needs its `uuid` and `name`. Regenerate templates after changing `required`.

## Source

`src/opentide/cli/services/lint.py`
