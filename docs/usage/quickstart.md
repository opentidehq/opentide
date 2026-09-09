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
pip install 'opentide==0.1.0'
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
```

</Step>

<Step>

### Generate framework artifacts

Schemas, templates, and indexes must exist before validation:

```bash
opentide generate
```

This runs the full pipeline: docs → exports → vocabs → templates → schemas → snippets.

```text
✓ vocabularies loaded
✓ templates written        .opentide/templates/
✓ schemas written          .opentide/schemas/
✓ IDE router               .opentide/schemas/opentide.schema.json
generate: complete
```

Generation runs first because validation checks objects against these generated schemas — no schemas, nothing to validate against.

</Step>

<Step>

### Validate content

```bash
opentide validate
opentide validate --strict   # warnings also fail (exit 1) — use in CI
```

On success the process exits `0`. For structured detail add `--json`, which writes one result document to stdout (see [Exit codes](../cli/exit-codes.md)). If validation fails, see [Troubleshooting](./troubleshooting.md).

Validate a single platform query language:

```bash
opentide validate query --platform sentinel
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
opentide deploy --platform sentinel --dry-run
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
