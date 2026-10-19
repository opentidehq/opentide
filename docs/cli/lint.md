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
| `metadata` | Reports a missing `metadata.author` or `metadata.organisation` | Not auto-fixed |

Default (no `--check`) runs both. YAML formatting and orphan doc pages are not in this command yet. Vocabulary pins ship inside OpenTide, so lint does not check them: OpenTide's own CI checks the bundled pins against the specifications whenever they change.

Lint walks `objects/{threats,objectives,rules}/**/*.yaml` and does not rebuild the object registry.

## Flags

| Flag | Purpose |
|------|---------|
| `--check` | Repeatable. `filenames` or `metadata` |
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
| Object has no `name` | `error` | The `name:` key when it is present but empty, else `null` |
| Filename is not `slugify(name)` | `warning` | `null` |
| `metadata.author` or `metadata.organisation` missing | `info` | The `metadata:` key, or `null` when there is no `metadata` block |

Severity is for sorting and triage only. `--strict` exits `1` on any finding, whatever its severity.

## Source

`src/opentide/cli/services/lint.py`
