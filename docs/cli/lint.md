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
| `placeholders` | Reports each value [`opentide new`](./new.md) filled in for you, marked `# opentide:placeholder` | Not auto-fixed |

Default (no `--check`) runs all three. YAML formatting and orphan doc pages are not in this command yet. Vocabulary pins ship inside opentide, so lint does not check them: opentide's own CI checks the bundled pins against the specifications whenever they change.

Lint walks `objects/{threats,objectives,rules}/**/*.yaml` and does not rebuild the object registry.

## Flags

| Flag | Purpose |
|------|---------|
| `--check` | Repeatable. `filenames`, `metadata` or `placeholders` |
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

When more than one severity is left, the count splits them. When a filename finding can be fixed by renaming, the count is followed by the command that does it. A file renamed by `--fix` gets `note: renamed from <old path>`; the count leaves it out and ends with `· 1 fixed`, so a run whose findings were all fixed prints `✓ 3 files clean · 1 fixed`. Under `--strict`, findings fail the run: the count prints as `✗ 2 findings in 1 file` and `failure.code` is `issues_found`. A workspace with no object files passes, and says where it looked.

### JSON findings

`--json` returns the same findings under `findings`, with `count` and `fixed` totals. Every finding has these keys:

| Key | Value |
|-----|-------|
| `check` | `filenames`, `metadata` or `placeholders` |
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

A placeholder adds `code` (`placeholder`) and `help`, the step that clears it. A filename mismatch adds `expected`, the path the file should have. Under `--fix` it also has `fixed`, and `from` (the old path) when the file was renamed. `fixed` is `false` when a file already exists at `expected`.

| Finding | `severity` | `yaml_line` |
|---------|------------|-------------|
| Object YAML does not parse, or is not a mapping | `error` | `null` |
| Object has no `name` | `error` | The `name:` key when it is present but empty or not a string, else `null` |
| Filename is not `slugify(name)` | `warning` | `null` |
| `metadata.author` or `metadata.organisation` missing | `info` | The `metadata:` key, or `null` when there is no `metadata` block |
| A value marked `# opentide:placeholder` | `warning` | The marked line |

Severity is for sorting and triage only. `--strict` exits `1` on any finding, whatever its severity.

### Placeholders

`opentide new` writes a valid object at once, so a required value nobody has chosen yet gets a stand-in: the first value the schema allows (an ATT&CK technique, a category) or `...` for free text. Each such line ends in `# opentide:placeholder`, and `lint` reports it as a `placeholder` warning. The message names the key, or the key and index for an item of a list (`mitre_attack[0]`), and the finding carries `line`, `column` and `end_column` (1-based, end exclusive) around the value, or around the key of a block scalar:

```text illustrative
[placeholders/warning] objects/threats/credential-dumping.yaml:12:7: mitre_attack[0] holds a placeholder value written by opentide new
  help: replace the value, then delete the '# opentide:placeholder' comment
```

Plain `lint` and `validate` still pass, so a draft can be committed: the commit hook runs `validate --strict` only. The CI pipeline from `opentide setup ci` also runs `lint --strict`, which fails until every marked value is replaced and its marker deleted. A placeholder looks like a real choice, so until then `generate` exports it like one (an ATT&CK technique in the coverage layer, for instance).

## Source

`src/opentide/cli/services/lint.py`
