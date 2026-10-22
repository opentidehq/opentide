---
title: opentide share
description: Publish Tide objects to a MISP destination as one Event per object.
---

# opentide share

Publishes threat, objective, and rule documents to the destinations in `.opentide/configurations/sharing.toml`. `opentide share` is `opentide share push`.

Sharing is not deployment. A MISP block is not a detection platform, and CrowdStrike or HarfangLab query validation is unchanged.

## Commands

```bash
opentide share push
opentide share preview
opentide share status
opentide share retract
opentide share targets
```

| Command | Effect |
|---------|--------|
| `push` | Create or update one MISP Event per selected object |
| `preview` | Same decision as push, with no request and no ledger write. An unset API key does not block it. `push --dry-run` is the same command |
| `status` | Compare the local ledger with the current object. No remote call |
| `retract` | Unpublish the matched event. `--delete --yes` removes the event and the ledger line |
| `targets` | List integration, name, enabled, `max_tlp`, and URL. The API key is never printed |

## Options

| Flag | Commands | Purpose |
|------|----------|---------|
| `--target` | push, preview, status, retract | Block `name`. Repeatable. Omitted means every enabled block |
| `--uuid` | push, preview, status, retract | Limit to these object UUIDs |
| `--type` | push, preview, status, retract | `threat`, `objective`, or `rule` |
| `--file` | push, preview, status, retract | Limit to these files |
| `--dry-run` | push | Preview |
| `--publish` / `--no-publish` | push | Override the block `publish` flag for this run |
| `--workers` | push, preview, retract | Parallel workers for one destination. Default `1` |
| `--changed` | push | Share only objects the default-branch CI diff changed. `opentide share --changed` is the same flag |
| `--since COMMIT` | push | With `--changed`: diff from this full commit SHA, branch, `origin/<branch>` or `refs/...` name instead of the push's baseline. Also runs outside CI |
| `--delete` | retract | Delete the remote event |
| `--yes` | retract | Required with `--delete` |

Filters only narrow the selection. An unknown `--target`, a disabled block named by `--target`, or no enabled block is a preflight failure. `max_tlp` is the ceiling: `red` shares TLP:RED, and there is no `--allow-tlp-red`.

`--changed` starts where the default-branch `opentide deploy --strategy RELEASE` diff starts: the first parent of the commit that triggered the run (`GITHUB_SHA`, `BUILD_SOURCEVERSION`), or on GitLab `CI_COMMIT_BEFORE_SHA` when it is set and not all zeros, else `CI_COMMIT_SHA`'s first parent. It ends at the checkout's `HEAD`, not at the triggering commit. The [generated share job](../usage/workflows/ci-cd.md) checks out the default branch's tip after the production deploy, so the range also holds that deploy's write-back. In a checkout of the triggering commit the range is the deploy's. `--since COMMIT` replaces the start; the range still ends at `HEAD`. It keeps `.yaml` and `.yml` files that sit directly in the configured threat, objective, and rule directories. Added and modified files are included. Deletions are ignored, and a deletion does not retract. It runs on a push to the default branch in GitHub Actions, GitLab CI, or Azure Pipelines. On a pull request it is a preflight failure and makes no request; outside those three it is one too, unless `--since` names the start. `--since` without `--changed` is a usage error (exit `2`). An empty diff exits `0`. With no `--target` and no enabled block, `--changed` also exits `0`. An unknown or disabled `--target` is still `scope_no_match`.

```bash
opentide share push --changed
opentide share push --changed --since <commit-sha>   # from that commit to HEAD
```

A rule passes a block's `rule_statuses` (default `["PRODUCTION"]`) when an enabled platform block (`configurations.<platform>` with `enabled: true`) has a status in that list. The root `status` counts only when no enabled platform block has one. A rule that does not pass is `skipped_status`.

Block statuses are the ones deploy uses and promotion rewrites, so once promotion's write-back has landed, a rule whose enabled block reads `PRODUCTION` is shared even though its root `status` still reads `STAGING`. Every enabled block counts, including blocks for platforms the repository has not enabled, which deploy skips. The generated CI share job runs after the production deploy and reads the default branch's tip, which holds promotion's write-back, so a rule that deploy promoted is shared in the same run.

`push` and `preview` validate each object that passes the type, status, and TLP filters. `sharing-config` runs as part of loading `sharing.toml`. A literal API key is a warning and is replaced with `[REDACTED]` if it would otherwise appear.

## State

Successful creates, updates, and retractions are recorded in `.opentide/states/sharing.jsonl`. Skips and failures leave the file unchanged. `preview` writes nothing. Setup gitignores `.opentide/states/sharing.jsonl` only: the file is a cache, while `.opentide/states/deployment/` holds [deployment state](../usage/concepts/deployment-state.md) that must be committed.

## Exit codes

Share uses two codes in addition to the [global exit codes](./exit-codes.md):

| Code | Meaning |
|-----:|---------|
| `0` | No object failed. Skips are not failures, so a run that only skips exits `0` |
| `1` | Preflight failure, or at least one object failed for a reason other than authentication or connectivity, and nothing succeeded |
| `2` | Every object failure is authentication or connectivity, and nothing succeeded |
| `3` | At least one object succeeded and at least one failed |

With `--json`, the document includes `records`: one entry per object UUID and block, with `action`, `reason` on skips and failures, and `remote_event_id` when MISP assigned one.
