---
title: CI/CD
description: Gate detection content on every PR and deploy on merge — GitHub, GitLab, and Azure pipelines with staging, promotion, and secrets.
---

# CI/CD integration

The point of detection-as-code is that a machine enforces quality. A good OpenTide pipeline **validates every pull request** and **deploys on merge**, promoting to production as a controlled step.

```mermaid
flowchart LR
  pr["Pull request"] --> validate["generate + validate --strict + validate query"]
  validate -->|pass| merge["Merge to main"]
  merge --> stage["deploy (staging)"]
  stage --> promote["promote → PRODUCTION"]
```

## Scaffold with setup

The fastest start is to let OpenTide write the pipeline for you:

```bash
opentide setup ci --ci github --platform sentinel --yes
opentide setup ci --ci gitlab --platform sentinel --platform splunk --yes
opentide setup ci --ci azure  --python-version 3.12 --yes
```

`setup ci` discovers enabled platforms from `.opentide/configurations/platforms/` — it does not take `--platform` flags (those belong on `setup platforms` or the parent `opentide setup --platform` callback).

| Flag | Default | Purpose |
|------|---------|---------|
| `--staging` / `--no-staging` | staging on | Include the staging deploy stage |
| `--promotion` / `--no-promotion` | promotion on | Include the promotion stage |
| `--promotion-target` | `PRODUCTION` | Target status for promotion |
| `--python-version` | `3.12` | CI Python version |

## Stage 1 — validate every PR

This is the non-negotiable gate. It needs no secrets (query validation checks syntax, not connectivity).

```yaml
# .github/workflows/validate.yml
name: validate
on: pull_request
jobs:
  validate:
    runs-on: ubuntu-latest
    env:
      OPENTIDE_REPO_ROOT: ${{ github.workspace }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install opentide
      - run: opentide generate
      - run: opentide validate --strict
      - run: opentide validate query --platform sentinel
```

## Stage 2 — deploy on merge (staging)

Runs on push to `main`, deploying rules in their current status. This is where platform **secrets** are needed.

```yaml
# .github/workflows/deploy.yml
name: deploy
on:
  push:
    branches: [main]
jobs:
  deploy-staging:
    runs-on: ubuntu-latest
    environment: staging
    env:
      OPENTIDE_REPO_ROOT: ${{ github.workspace }}
      DEPLOYMENT_PLAN: staging
      AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
      AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
      AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
      AZURE_WORKSPACE_ID: ${{ secrets.AZURE_WORKSPACE_ID }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install opentide
      - run: opentide generate
      - run: opentide deploy --platform sentinel --dry-run   # preview in logs
      - run: opentide deploy --platform sentinel
```

## Stage 3 — promote to production

Promotion is a deliberate step — gate it behind a protected environment or manual approval.

```yaml
  promote-production:
    needs: deploy-staging
    runs-on: ubuntu-latest
    environment: production          # require reviewers on this environment
    env:
      OPENTIDE_REPO_ROOT: ${{ github.workspace }}
      DEPLOYMENT_PLAN: production
      AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
      AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
      AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
      AZURE_WORKSPACE_ID: ${{ secrets.AZURE_WORKSPACE_ID }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install opentide
      - run: opentide deploy --platform sentinel
```

## Secrets

Never commit platform credentials. Inject them as CI secrets and reference them from your platform TOML with `${VAR}` — see [Configuration → credentials](../configuration.md#credentials).

| Where | How |
|-------|-----|
| **GitHub** | Repository/environment secrets → `env:` or `${{ secrets.X }}` |
| **GitLab** | CI/CD variables (masked, protected) → available as env vars |
| **Azure** | Pipeline variables / variable groups (secret) → env vars |

Scope production secrets to a protected environment so PR builds from forks cannot read them.

## GitLab CI

```yaml
# .gitlab-ci.yml
stages: [validate, deploy]

validate:
  stage: validate
  image: python:3.12
  variables:
    OPENTIDE_REPO_ROOT: $CI_PROJECT_DIR
  script:
    - pip install opentide
    - opentide generate
    - opentide validate --strict
    - opentide validate query --platform sentinel

deploy-staging:
  stage: deploy
  image: python:3.12
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  variables:
    OPENTIDE_REPO_ROOT: $CI_PROJECT_DIR
    DEPLOYMENT_PLAN: staging
  script:
    - pip install opentide
    - opentide generate
    - opentide deploy --platform sentinel
```

## Azure Pipelines

```yaml
# azure-pipelines.yml
trigger: [main]
pool: { vmImage: ubuntu-latest }
variables:
  OPENTIDE_REPO_ROOT: $(Build.SourcesDirectory)
steps:
  - task: UsePythonVersion@0
    inputs: { versionSpec: '3.12' }
  - script: pip install opentide
  - script: opentide generate && opentide validate --strict
  - script: opentide validate query --platform sentinel
```

## JSON output for gates

Every command accepts `--json` for machine-readable results. Parse the `ok` field and issue lists in downstream gates:

```bash
opentide validate --strict --json
```

See [CLI → JSON output](../../cli/index.md) and [exit codes](../../cli/exit-codes.md).

## Documentation in CI

```bash
opentide generate docs --flavor github
```

Flavor auto-detects from `GITHUB_ACTIONS`, GitLab `CI`, or Azure `TF_BUILD`; override with `--flavor`. See [`generate docs`](../../cli/generate.md).

## Migrating from submodule CI

Remove `submodules: recursive` from checkout and install from PyPI instead. Replace legacy Orchestration scripts:

| Legacy script | CLI replacement |
|---------------|-----------------|
| `Orchestration/validate.py` | `opentide validate` |
| `Orchestration/generate.py` | `opentide generate` |
| `Orchestration/deploy.py` | `opentide deploy` |
| `Orchestration/document.py` | `opentide generate docs` |

See the [migration guide](../migration/index.md).
