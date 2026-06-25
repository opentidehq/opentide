---
title: Quickstart
description: Validate, generate schemas, and inspect a detection repository in five minutes.
---

This walkthrough assumes you have a detection content repository with `objects/` content, or that you scaffold one with `opentide setup`.

<Steps>

<Step>

### Install and point at your repo

```bash
pip install opentide
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
```

</Step>

<Step>

### Generate framework artifacts

Schemas, templates, and indexes must exist before strict validation:

```bash
opentide generate
```

This runs the full pipeline: docs → exports → vocabs → templates → schemas → snippets.

</Step>

<Step>

### Validate content

```bash
opentide validate
opentide validate --strict
```

`--strict` treats warnings as failures — use in CI.

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
