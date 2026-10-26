---
name: steward
description: Drive an opentide pull request to mergeable — read each CI job's failure, reproduce it locally, fix and push, answer review threads, keep the changelog and docs in step, and know what never to do (skip tests, force-push shared branches, hand-edit uv.lock). Use when babysitting or autofixing a PR, when CI is red, or after review comments arrive.
---

# Steward — driving an opentide PR to green

Trunk is `development`. A PR is done when every check on its **current head** is green, it
merges cleanly into its base, and no review thread waits on you.

## CI jobs and how to reproduce each

| Check | What it runs | Reproduce locally |
|-------|--------------|-------------------|
| **Lint** | ruff check + format, ty, `uv build`, `twine check`, vocab drift gate (only when bundled vocab/pins/lockfile change) | `scripts/ci-local.sh --quick` |
| **Test (3.10 … 3.14)** | unit suite, `-n 4`; coverage gate on 3.14 only | `scripts/ci-local.sh` (`--full` adds the gate) |
| **E2E (3.14, shard N/4)** | `cli_e2e` + `cli_smoke`, split by `.test_durations_e2e` | `uv run pytest tests/ -m "cli_e2e or cli_smoke" -q --no-cov -n 4 --splits 4 --group N --durations-path .test_durations_e2e` |
| **GitLab CI lint** | glint + gitlab-ci-verify on rendered pipelines | `scripts/ci-local.sh --full` (installs the linters) |
| **CLI Windows smoke** | console launcher + case-insensitive `migrate objects` | no local equivalent; reason about it (below) |
| **CodeQL** | Python + Actions, `security-extended` | [`codeql`](../codeql/SKILL.md) |

Serial output is easier to read: `PYTEST_WORKERS=0 scripts/ci-local.sh`.

## Reading failures

- **Only on 3.10** — syntax or stdlib newer than 3.10 (`tomllib`, `typing.Self`, `except*`,
  PEP 695 generics). The package supports `>=3.10`.
- **Only on Windows** — `\` paths, CRLF (`write_text` without `newline=`), case-insensitive
  names (`Objects` vs `objects`), console encoding.
- **Only in one E2E shard** — run that shard; then `PYTEST_WORKERS=0` on the single test. A
  test that passes serially and fails under xdist leaks global state (registry caches,
  `os.environ` flags such as `VALIDATION_ERROR_RAISED`, cwd) — fix the leak, don't pin order.
- **Coverage gate** — the gate reads the 3.14 cell. Cover the new lines; do not add
  `pragma: no cover` to code that can be tested or widen `[tool.coverage.run].omit`.
- **Snapshot (syrupy) failures** — update with `--snapshot-update` only when the output
  change is the intended one, and say so in the commit body.
- **ty after a ty bump** — usually a rule rename; see [`uv`](../uv/SKILL.md) "Dependency upgrades".
- **Vocab drift gate** — bundled vocabulary is generated from `opentidehq/specifications`;
  fix it upstream and re-sync with `scripts/build/sync_vocabularies.py`, never by hand.
- **Fails on `development` too** — not this PR's. Say so once on the PR with the failing
  check and link the fix if one exists; port the fix into this PR when it is small.

"Flake" is not a diagnosis. Re-run once only for an infrastructure death (checkout, install,
runner lost) and treat a second failure as real.

## Never

- Skip, `xfail`, quarantine or loosen a test to get green.
- `git push --no-verify`, empty commits or close/reopen to re-trigger CI.
- Force-push, rebase or amend a branch someone else is working on; merge the base in instead.
- Hand-edit `uv.lock`, `src/opentide/_version.py`, generated schemas or bundled vocabulary.
- Bump the package version — releases are tags ([`release-management`](../release-management/SKILL.md)).

## Every push

1. `scripts/ci-local.sh --full` green (it is the pre-push hook; cloud sessions don't install it).
2. The diff passes [`review-checklist`](../review-checklist/SKILL.md), including a regression
   test that fails without the fix.
3. User-visible change → `## [Unreleased]` in `CHANGELOG.md`; CLI/MCP/SDK surface change →
   `docs/` ([`docs-maintenance`](../docs-maintenance/SKILL.md)).
4. Conventional Commit subject (`fix(scope): …`), body explains the failure a user saw.

## Review threads

Implement small, local asks (renames, a missing test, a nit) and reply with the commit.
Larger design asks on someone else's PR: reply with a proposal and let the author decide.
Resolve threads you addressed. Bot findings are claims — trace a real input to the failure
before building anything for it, and say why when you decline.

## Merge state

A conflict with `development`: merge `origin/development` into the branch, regenerate
`uv.lock` with `uv lock` if it conflicts, re-run `scripts/ci-local.sh`, push. Stacked PRs
(base is another branch) merge in the order the stack comment shows.
