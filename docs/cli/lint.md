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

Default (no `--check`) runs both. YAML formatting and orphan doc pages are not in this command yet. Vocabulary pins ship inside opentide, so lint does not check them: opentide's own CI checks the bundled pins against the specifications whenever they change.

Lint walks `objects/{threats,objectives,rules}/**/*.yaml` and does not rebuild the object registry.

## Flags

| Flag | Purpose |
|------|---------|
| `--check` | Repeatable. `filenames` or `metadata` |
| `--fix` | Apply safe filename renames |
| `--strict` | Exit `1` when any finding exists (CI gate). Default is report-only |

`--fix` is idempotent.

## Output

Human output prints each finding as a code frame, like [`validate`](./validate.md), then one line counting them. The [tutorial](../usage/tutorial.md) catalogue passes both checks:

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

! 2 findings in 1 file
→ opentide lint --fix · rename 1 file(s) to match their names
```

When a filename finding can be fixed by renaming, the count is followed by the command that does it. A file renamed by `--fix` gets `note: renamed from <old path>`, and the count ends with `· 1 fixed`. Under `--strict`, findings fail the run: the count prints as `✗ 2 findings in 1 file` and `failure.code` is `issues_found`. A workspace with no object files passes, and says where it looked.

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
| `code` | `filename_mismatch`, `name_missing`, `metadata_recommended`, or `yaml_parse`. `opentide explain <code>` describes it |
| `field_path` | The key the finding is about (`["metadata"]`), or `[]` |
| `line`, `column`, `end_column` | One-based position of that key, or of the YAML error. `null` when unknown |
| `help` | What to do, or `null` |
| `fix` | Always `null`: a rename is not a text edit. `opentide lint --fix` renames |
| `explain` | `opentide explain <code>` |

`summary` counts the object `files` read, the `findings` and the `fixed` ones.

A filename mismatch adds `expected`, the path the file should have. Under `--fix` it also has `fixed`, and `from` (the old path) when the file was renamed. `fixed` is `false` when a file already exists at `expected`.

| Finding | `severity` | `yaml_line` |
|---------|------------|-------------|
| Object YAML does not parse, or is not a mapping | `error` | `null` |
| Object has no `name` | `error` | The `name:` key when it is present but empty or not a string, else `null` |
| Filename is not `slugify(name)` | `warning` | `null` |
| `metadata.author` or `metadata.organisation` missing | `info` | The `metadata:` key, or `null` when there is no `metadata` block |

Severity is for sorting and triage only. `--strict` exits `1` on any finding, whatever its severity.

## Source

`src/opentide/cli/services/lint.py`
