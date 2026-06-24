# CodeQL — OpenTide

Static analysis for Python and GitHub Actions workflows. One workflow, no duplicate scans.

## When to use

- Adding or changing security-sensitive Python or workflow code
- Investigating CodeQL alerts on a PR
- Running analysis locally before a large security-related change

## CI workflow

[`.github/workflows/codeql.yml`](../../../.github/workflows/codeql.yml):

- **Languages:** `python` and `actions` in one matrix job (categories `/language:python` and `/language:actions`)
- **Why both in the workflow:** PR code-scanning comparison requires the same `(codeql.yml) /language:python` category registered on `development`; Code Quality dynamic scans alone leave PR checks in a NEUTRAL "configuration not found" state
- **Triggers:** push to `main`/`development`, all PRs, weekly schedule
- **Queries:** `security-extended`
- **Python deps:** `uv sync --group dev` before analyze

Code Quality may also run a dynamic Python scan on push; if duplicate alerts appear, disable Python in Code Quality settings and rely on this workflow.

## Local analysis

```bash
scripts/codeql-local.sh              # create DB + analyze Python (~40–60s cold)
scripts/codeql-local.sh --install    # brew install CodeQL CLI only
```

Mirrors the Python path in CI. Not suitable for pre-commit or pre-push hooks.

Output: `codeql-results.sarif` at repo root.

## When to run locally vs CI

| Situation | Run |
|-----------|-----|
| Normal feature work | CI only |
| Workflow or auth changes | `scripts/codeql-local.sh` before push |
| Fixing a CodeQL alert | Local repro, then push fix |
| Pre-commit / pre-push | **Do not** — too slow |

## Related

- `AGENTS.md` — CI overview
- [`github-actions-templates`](../github-actions-templates/SKILL.md) — workflow authoring
