---
title: Quickstart
description: Validate, generate schemas, and inspect a detection repository in five minutes.
---

# Quickstart

This walkthrough assumes you have a detection repository with `objects/` content, or that you scaffold one with `opentide setup`.

## 1. Install and point at your repo

```bash
pip install "opentide[sentinel,cli]>=0.1"
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
```

## 2. Generate framework artifacts

Schemas, templates, and indexes must exist before strict validation:

```bash
opentide generate
```

This runs the full pipeline: vocabs → templates → schemas → snippets → exports → playbook-map → docs.

## 3. Validate content

```bash
opentide validate
opentide validate --strict
```

`--strict` treats warnings as failures — use in CI.

Validate a single platform query language:

```bash
opentide validate query --platform sentinel
```

## 4. Inspect the catalogue

```bash
opentide info
opentide info rules
opentide --json info --technique T1059 coverage
```

## 5. Dry-run deployment

```bash
opentide deploy --platform sentinel --dry-run
```

## 6. Generate object documentation

```bash
opentide document
```

Writes markdown pages for rules, objectives, and threats under the configured docs folder.

## New repository from scratch

```bash
opentide setup --yes \
  --name "SOC Detections" \
  --org "Example Corp" \
  --platform sentinel \
  --ci github \
  --mcp cursor \
  --skills generic

opentide generate
opentide validate
```

## Next steps

- [Detection-as-code workflow](./workflows/detection-as-code.md)
- [CI/CD integration](./workflows/ci-cd.md)
- [CLI reference](../cli/index.md)
