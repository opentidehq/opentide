# Jujutsu stacked pull requests

Use when creating, reviewing, submitting, or rebasing **stacked PRs** in OpenTide.
**Do not use Git branching workflows or Graphite (`gt`)** — this repo standardises on [Jujutsu (`jj`)](https://github.com/jj-vcs/jj).

## When to use

- Splitting work into dependent PRs (stacked changes)
- Submitting or updating a PR stack to GitHub
- Rebasing after a stack PR merges
- Understanding stack comments on GitHub PRs

## Prerequisites

```bash
scripts/jj-setup.sh --remove-graphite   # once per machine
uv sync --group dev
uv run pre-commit install --install-hooks
```

Trunk branch: **`development`** (`development@origin` in jj).

### Git worktrees (Cursor / multiple checkouts)

Colocated jj lives in the **primary** git checkout. `scripts/jj-common.sh` runs `jj -R <primary>` so stack scripts work from any worktree without `jj workspace add`.

## Core concepts

| Git / Graphite | Jujutsu |
|----------------|---------|
| branch | **bookmark** |
| commit | **change** (mutable; identity = change-id) |
| `git rebase` | `jj rebase` (bookmarks follow) |
| `gt stack` | bookmark stack + `scripts/jj-stack-*` |
| stacked PR base | each PR targets bookmark **below** it; bottom targets `development` |

## Create a stack (agent workflow)

```bash
jj git fetch
jj new development@origin -m "feat(scope): first change"
# ... edit files ...
jj bookmark create feat/part-1

jj new -m "feat(scope): second change (depends on part-1)"
# ... edit ...
jj bookmark create feat/part-2

jj new -m "feat(scope): third change"
jj bookmark create feat/part-3

scripts/jj-stack-status.sh
scripts/ci-local.sh --full
scripts/jj-stack-submit.sh feat/part-3    # or --dry-run first
```

**Rules**

1. One logical concern per change / PR
2. Conventional commit message on each change (`jj describe` / `-m`)
3. Bottom of stack merges to `development` first
4. After merge: `jj git fetch` → `jj abandon <merged-bookmark>` → `jj rebase -d development@origin` → re-submit

## Submit stack to GitHub

```bash
scripts/jj-stack-submit.sh <top-bookmark> [--draft] [--dry-run]
```

This script:

1. Walks ancestors from top bookmark to `development@origin`
2. `jj git push --bookmark` each level
3. `gh pr create` with correct **base** (stacked, not all targeting `development`)

GitHub Actions posts **stack navigation** comments on each PR automatically.

## After a PR merges (sync stack)

```bash
jj git fetch
jj abandon feat/part-1                    # merged bookmark
jj rebase -d development@origin           # use @origin — not bare development
scripts/jj-stack-submit.sh feat/part-3    # refresh remaining PRs
```

Merge order is always **bottom → top**.

## Review feedback on middle of stack

```bash
jj new feat/part-2                        # edit change in place
# ... fix ...
jj squash                                 # or jj commit for new snapshot
scripts/ci-local.sh --full
scripts/jj-stack-submit.sh feat/part-3    # updates PRs + stack comments
```

## CI and local checks

| When | Command |
|------|---------|
| Every commit (fast) | pre-commit hooks |
| Before submit | `scripts/ci-local.sh --full` |
| Pre-push (automatic) | same via pre-commit |

CI runs on **all** PRs (including stacks whose base is a feature bookmark).

## Stack comments on GitHub

Workflow: `.github/workflows/stack-comment.yml`
Script: `scripts/github_stack_comment.py`

Each PR gets a comment with position in stack, merge order, and links. Agents should read this comment before reviewing.

## Forbidden

- `gt` / Graphite commands
- Creating parallel git branches for stacked work without jj
- Merging stack PRs top-down
- `git push --force` on shared branches (use `jj git push --bookmark`)
- Rebasing to `development` without `@origin` after remote merges

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `jj not found` | `scripts/jj-setup.sh` |
| worktree / no `.jj` here | `scripts/jj-setup.sh` (uses `jj -R` via `scripts/jj-common.sh`) |
| immutable commits on rebase | use `development@origin` not `development` |
| PR shows wrong diff | check PR **base** branch matches bookmark below |
| no stack comment | wait for `stack-comment` workflow; re-run if needed |
| bookmark conflict | `jj bookmark list`, `jj git fetch`, resolve with `jj bookmark move` |

## Reference

- `AGENTS.md` — project rules + jj section
- `scripts/jj-stack-status.sh` — local stack view
- `scripts/jj-stack-submit.sh` — push + gh PR stack
- [jj bookmarks](https://github.com/jj-vcs/jj/blob/main/docs/bookmarks.md)
