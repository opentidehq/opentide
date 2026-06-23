# CodeQL — OpenTide

Static analysis for Python and GitHub Actions workflows. One workflow, no duplicate scans.

## When to use

- Adding or changing security-sensitive Python or workflow code
- Investigating CodeQL alerts on a PR
- Running analysis locally before a large security-related change

## CI workflow

[`.github/workflows/codeql.yml`](../../../.github/workflows/codeql.yml):

- **Languages:** `actions` only (GitHub Actions workflow scanning)
- **Python:** via **GitHub Code Quality** (Settings → Code security → Code Quality, or `PATCH /repos/{owner}/{repo}/code-quality/setup` with `state: configured` and `languages: ["python"]`)
- **Triggers:** push to `main`/`development`, all PRs, weekly schedule
- **Queries:** `security-extended`

Enable Code Quality for Python scanning. Do **not** add `python` to `codeql.yml` — that duplicates the Code Quality CodeQL run.

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
