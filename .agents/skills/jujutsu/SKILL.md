# Jujutsu (jj) — primary version control

Use for **all** version control in OpenTide: daily work, amends, rebases, pushes, and stacked PRs.

**Git is transport only** — sync and publish to GitHub via `jj git fetch` / `jj git push --bookmark`. Coding agents must **not** use `git commit`, `git checkout -b`, `git branch`, `git merge`, `git rebase`, or Graphite (`gt`).

Skill path: `.agents/skills/jujutsu/SKILL.md`

## When to use

- Starting or continuing any code change
- Committing, amending, or describing work
- Rebasing on trunk after merges
- Pushing a bookmark and opening/updating a PR
- Stacked PR workflows (see § Stacked PRs below)

## Prerequisites

```bash
scripts/jj-setup.sh              # once per machine (colocated jj in repo root)
uv sync --group dev
uv run pre-commit install --install-hooks
```

Trunk: **`development@origin`** (always prefer `@origin` after remote activity).

**Default:** one clone, colocated jj (`jj git init --colocate`). Start work with `jj git fetch` then `jj new development@origin`. Secondary git worktrees are optional — run `scripts/jj-setup.sh` there (`jj git init --git-repo=.`).

## Mental model

| Old habit (git) | Jujutsu |
|-----------------|---------|
| `git status` | `jj status` |
| `git log` | `jj log` |
| `git checkout -b feat/x` | `jj new development@origin -m "…"` then `jj bookmark create feat/x` |
| `git add` + `git commit` | Edit files — jj snapshots `@` automatically; `jj describe -m "…"` |
| `git commit --amend` | `jj squash` or edit `@` with `jj new` then squash |
| `git rebase main` | `jj rebase -d development@origin` |
| `git push origin branch` | `jj git push --bookmark <bookmark>` |
| `git pull` | `jj git fetch` then rebase if needed |
| branch name | **bookmark** |

Changes are **mutable** until pushed/shared; identity is the change-id, not the commit hash.

## Coding agent workflow (every task)

```bash
jj git fetch
jj status
jj log -r 'development@origin..@' --reversed   # optional: what's in flight
```

### Start a single change

```bash
jj new development@origin -m "feat(scope): short description"
# ... edit files (jj auto-snapshots working copy) ...
jj describe -m "feat(scope): refined message"    # if message changed
jj bookmark create feat/short-slug
scripts/ci-local.sh --full
scripts/jj-submit.sh feat/short-slug             # push + gh pr create
```

### Amend current work (no new change)

```bash
# @ already has your bookmark — just edit, then:
jj describe -m "fix(scope): updated message"
scripts/ci-local.sh --full
jj git push --bookmark feat/short-slug
```

### After trunk moves or a PR merges

```bash
jj git fetch
jj abandon <merged-bookmark>                   # optional cleanup
jj rebase -d development@origin
jj git push --bookmark <still-open-bookmark>   # refresh PR
```

## Stacked PRs

When work splits into dependent layers, stack **bookmarks** (one concern per change):

```bash
jj new development@origin -m "feat(scope): layer 1"
jj bookmark create feat/part-1
jj new -m "feat(scope): layer 2"
jj bookmark create feat/part-2
scripts/jj-stack-status.sh
scripts/jj-stack-submit.sh feat/part-2         # bottom → top PRs
```

Merge order on GitHub: **bottom → top**. Read the **Stack navigation** comment on each PR.

Details: same commands as above; submit via `scripts/jj-stack-submit.sh` not `jj-submit.sh`.

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/jj-setup.sh` | Install jj, colocate repo (or init extra checkout) |
| `scripts/jj-common.sh` | `jj_cmd` helper (sourced by other scripts) |
| `scripts/jj-submit.sh` | Push one bookmark + `gh pr create` to trunk |
| `scripts/jj-stack-status.sh` | View stack from trunk to `@` |
| `scripts/jj-stack-submit.sh` | Push stack + stacked `gh pr create` |

## pre-commit / pre-push

Hooks are installed with `uv run pre-commit install`. They run on **`jj git push`** (colocated git backend). Before push:

```bash
uv run pre-commit run --all-files    # optional explicit run
scripts/ci-local.sh --full           # matches pre-push gate
```

Do **not** run `git commit` to trigger hooks — jj records changes; push via `jj git push --bookmark`.

## Forbidden (coding agents)

| Command | Use instead |
|---------|-------------|
| `git commit`, `git add` | edit + `jj describe`; jj snapshots |
| `git checkout -b`, `git switch -c` | `jj new` + `jj bookmark create` |
| `git merge`, `git rebase` | `jj rebase`, `jj squash` |
| `git push`, `git push --force` | `jj git push --bookmark` |
| `gt`, Graphite | jj bookmarks + stack scripts |

Read-only `gh` for PR status is fine. Avoid `git` except what setup scripts need internally.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `jj not found` | `scripts/jj-setup.sh` |
| no `.jj` in checkout | `scripts/jj-setup.sh` |
| wrong parent / immutable error | `jj rebase -d development@origin` (not bare `development`) |
| no bookmark on `@` | `jj bookmark create <type>/<slug>` |
| PR wrong base (stack) | `scripts/jj-stack-submit.sh` sets bases; check stack comment |
| hooks didn't run | use `jj git push`, not raw `git push` |

## Reference

- `AGENTS.md` — project rules
- [jj docs](https://github.com/jj-vcs/jj/tree/main/docs)
- [bookmarks](https://github.com/jj-vcs/jj/blob/main/docs/bookmarks.md)
