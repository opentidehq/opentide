---
title: Quickstart
description: Validate, generate schemas, and inspect a detection repository in five minutes.
---

This walkthrough assumes you already have a detection content repository with `objects/` content, or that you scaffold one with `opentide setup`. It shows the core commands fast.

<Callout type="info">
Want to author objects from scratch and understand each step? Do the [Tutorial](./tutorial.md) instead — it builds a full threat → objective → rule chain end to end.
</Callout>

<Steps>

<Step>

### Install and point at your repo

```bash
pip install 'opentide==0.18.0'
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
```

</Step>

<Step>

### Generate framework artifacts

Schemas, templates, and indexes must exist before validation:

```bash
opentide generate
```

This runs the full pipeline: docs → exports → vocabs → templates → schemas → snippets. On a repo that already has objects, exports include ATT&CK navigator JSON and `objects.export.json` (actor IDs are enriched from the vocabulary). On a freshly scaffolded empty repo, docs and exports are empty artifacts and the rest of the pipeline still completes.

```text output-of="opentide generate"
✓ docs · 7 files · 1.2s · docs/
✓ exports · 3 files · 0.0s · .opentide/exports/
✓ vocabularies · 0 files · 0.0s
✓ templates · 4 files · 1.9s · .opentide/templates/
✓ schemas · 8 files · 2.6s · .opentide/
✓ snippets · 1 file · 0.0s · .vscode/
✓ Generated 23 files in 5.8s · 6 phases
```

Each finished phase prints one line on stderr (files written, time, destination); the outcome line is the only line on stdout. This is the output with `--no-color`, in a pipe or in CI; at a terminal the phases draw as a live checklist.

Generation runs first because validation checks objects against these generated schemas — no schemas, nothing to validate against.

</Step>

<Step>

### Validate content

```bash
opentide validate
opentide validate --strict   # warnings also fail (exit 1), except platform_not_enabled — use in CI
```

On success the process exits `0`. For structured detail add `--json`, which writes one result document to stdout (see [Exit codes](../cli/exit-codes.md)). If validation fails, see [Troubleshooting](./troubleshooting.md).

Check a platform's catalogue queries against the tenant. This needs tenant credentials; the vendor SDKs ship with the package. Without `--live` the command exits `2` and names the flag:

```bash
opentide validate query --platform sentinel --live
```

</Step>

<Step>

### Inspect the catalogue

```bash
opentide info
opentide info rules
opentide --json info --technique T1059 coverage
```

</Step>

<Step>

### Dry-run deployment

```bash
opentide deploy --platform sentinel --dry-run --strategy PREVIEW --all
```

</Step>

<Step>

### Generate object documentation

```bash
opentide generate docs
```

Writes markdown pages for rules, objectives, and threats under the configured docs folder.

</Step>

</Steps>

## New repository from scratch

```bash
opentide setup --yes \
  --name "SOC Detections" \
  --org "Example Corp" \
  --platform sentinel \
  --ci github

opentide setup platforms --sentinel --yes
opentide setup mcp --cursor --yes
opentide setup skills --yes --generic

opentide generate
opentide validate
```

## Next steps

- [Detection-as-code workflow](./workflows/detection-as-code.md)
- [CI/CD integration](./workflows/ci-cd.md)
- [CLI reference](../cli/index.md)
- [Normative specifications](/docs/specifications/)
