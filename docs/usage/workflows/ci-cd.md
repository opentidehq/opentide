---
title: CI/CD
description: Integrate opentide validate and generate into GitHub, GitLab, and Azure pipelines.
---

# CI/CD integration

Use `opentide setup ci` to scaffold pipeline files, or add steps manually to existing workflows.

## Scaffold with setup

Enable detection platforms first, then generate the CI **provider** workflow (`github`, `gitlab`, or `azure`):

```bash
opentide setup platforms --sentinel --yes
opentide setup ci github --yes
opentide setup ci gitlab --yes
opentide setup ci azure --python-version 3.12 --yes
```

`setup ci` discovers enabled platforms from `.opentide/configurations/platforms/` — it does not take `--platform` flags (those belong on `setup platforms` or the parent `opentide setup --platform` callback).

| Flag | Default | Purpose |
|------|---------|---------|
| `--staging` / `--no-staging` | staging on | Include staging deployment stage |
| `--promotion` / `--no-promotion` | promotion on | Include promotion stage |
| `--promotion-target` | `PRODUCTION` | Target status for promotion |
| `--python-version` | `3.12` | CI Python version |

## Minimal GitHub Actions job

```yaml
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install "opentide[sentinel,cli]>=0.1"
      - run: opentide generate
      - run: opentide validate --strict
        env:
          OPENTIDE_REPO_ROOT: ${{ github.workspace }}
      - run: opentide validate query --platform sentinel
        env:
          OPENTIDE_REPO_ROOT: ${{ github.workspace }}
```

## Environment variables in CI

Always set `OPENTIDE_REPO_ROOT` to the workspace root. Do **not** use git submodules for CoreTide — install from PyPI.

| Variable | When needed |
|----------|-------------|
| `OPENTIDE_REPO_ROOT` | Always |
| `DEPLOYMENT_PLAN` | Deploy and query validation stages |
| Platform secrets | Live deploy jobs (tenant-specific) |

## Migration from submodule CI

Remove `submodules: recursive` from checkout. Replace Orchestration scripts:

| Legacy script | CLI replacement |
|---------------|-----------------|
| `Orchestration/validate.py` | `opentide validate` |
| `Orchestration/generate.py` | `opentide generate` |
| `Orchestration/deploy.py` | `opentide deploy` |
| `Orchestration/document.py` | `opentide generate docs` |

See [Migration guide](../migration/index.md).

## JSON output for automation

Pass `--json` on any command for machine-readable results:

```bash
opentide validate --strict --json
```

Parse the `ok` field and issue lists in downstream gates.

## Document generation in CI

```bash
opentide generate docs --flavor github
```

Flavor auto-detects from `GITHUB_ACTIONS`, GitLab `CI`, or Azure `TF_BUILD`. Override with `--flavor` when needed. See [CLI generate](../../cli/generate.md).
