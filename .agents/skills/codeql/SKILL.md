---
name: codeql
description: >-
  Work with CodeQL in opentide: the codeql.yml workflow (Python, Rust and Actions), investigating or
  fixing code-scanning alerts, and running scripts/codeql-local.sh. Use when a PR shows CodeQL
  findings or when changing security-sensitive code or workflows.
---

# CodeQL — opentide

Static analysis for Python, the Rust workspace and GitHub Actions workflows. One workflow, no duplicate scans.

## When to use

- Adding or changing security-sensitive Python or workflow code
- Investigating CodeQL alerts on a PR
- Running analysis locally before a large security-related change

## CI workflow

[`.github/workflows/codeql.yml`](../../../.github/workflows/codeql.yml):

- **Action:** `github/codeql-action` **v4** (Node 24). Do not pin v3 — GitHub runners force Node 20 actions onto Node 24, and `analyze` then dies during SARIF upload with no `##[error]` line.
- **Languages:** `python`, `rust` and `actions` in one matrix job (categories `/language:python`, `/language:rust` and `/language:actions`)
- **Rust:** `build-mode: none` — CodeQL extracts the crates from source (GA since CodeQL 2.23.3), no cargo build or toolchain in the job. A pull request analyses Rust when it changes `crates/`, `bindings/`, `xtask/`, `Cargo.toml` or `Cargo.lock`
- **Why both in the workflow:** PR code-scanning comparison requires the same `(codeql.yml) /language:python` category registered on `development`; Code Quality dynamic scans alone leave PR checks in a NEUTRAL "configuration not found" state
- **Triggers:** push to `main`/`development`/`integration/unified-core`, PRs that change a language's files (each language analysed only when its files change), nightly schedule
- **Queries:** `security-extended`
- **Python deps:** `uv sync --group dev` before analyze

Code Quality may also run a dynamic Python scan on push; if duplicate alerts appear, disable Python in Code Quality settings and rely on this workflow.

## Local analysis

```bash
scripts/codeql-local.sh              # create DB + analyze Python (~40–60s cold)
scripts/codeql-local.sh --install    # brew install CodeQL CLI only
```

Mirrors the Python path in CI; Rust and Actions run in CI only. Not suitable for pre-commit or pre-push hooks.

Output: `codeql-results.sarif` at repo root.

## When to run locally vs CI

| Situation | Run |
|-----------|-----|
| Normal feature work | CI only |
| Workflow or auth changes | `scripts/codeql-local.sh` before push |
| Fixing a CodeQL alert | Local repro, then push fix |
| Pre-commit / pre-push | **Do not** — too slow |

## Related

- `.github/AGENTS.md` — CI overview
- [`github-actions-templates`](../github-actions-templates/SKILL.md) — workflow authoring
