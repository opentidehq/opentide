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
| `retract` | Unpublish the matched event. `--delete --yes` removes the event and the ledger line. Objects deleted from the repository are found through the ledger: `--type` matches the schema the ledger recorded, and `--file` never matches them |
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
| `--delete` | retract | Delete the remote event |
| `--yes` | retract | Required with `--delete` |

Filters only narrow the selection. A disabled block named by `--target`, or no enabled block, is a preflight failure (exit `1`). An unknown `--target` is a usage error: it exits `2` with `failure.code` `usage_invalid_choice` and the closest configured name in `failure.suggestion`, and the document keeps `preflight: "scope_no_match"` and `records: []`. `max_tlp` is the ceiling: `red` shares TLP:RED, and there is no `--allow-tlp-red`.

`--changed` uses the same commit range as the default-branch `opentide deploy --strategy RELEASE`. It keeps `.yaml` and `.yml` files that sit directly in the configured threat, objective, and rule directories. Added and modified files are included. Deletions are ignored, and a deletion does not retract. It runs on a push to the default branch in GitHub Actions, GitLab CI, or Azure Pipelines. On a pull request, or outside those three, it is a preflight failure and makes no request. An empty diff exits `0`. With no `--target` and no enabled block, `--changed` also exits `0`. A disabled `--target` is still `scope_no_match` (exit `1`); an unknown one exits `2` with `preflight: "scope_no_match"` kept.

```bash
opentide share push --changed
```

A rule passes a block's `rule_statuses` (default `["PRODUCTION"]`) when an enabled platform block (`configurations.<platform>` with `enabled: true`) has a status in that list. The root `status` counts only when no enabled platform block has one. A rule that does not pass is `skipped_status`.

Block statuses are the ones deploy uses and promotion rewrites, so once promotion's write-back has landed, a rule whose enabled block reads `PRODUCTION` is shared even though its root `status` still reads `STAGING`. Every enabled block counts, including blocks for platforms the repository has not enabled, which deploy skips. The CI share job reads the commit that triggered it, before the production deploy promotes, so a rule promoted by that deploy is shared the next time a push changes it, or by a `share push` run without `--changed`.

`push --publish` (or a block with `publish = true`) publishes an event whose content is unchanged but which is still unpublished, and reports it as `updated`; `preview` predicts the same from the ledger.

At a terminal, each target lists one row per object, like a deploy plan: `+ create`, `~ update`, `○ unchanged`, `× retract`, `○ skip` with the reason in words (`its TLP is above the target's max_tlp`), or `✗ fail`. A preview says `dry run, nothing is sent` beside the target and uses the planned words; `push` uses `created`, `updated`, … The JSON `action` values are the sharing spec's and do not change. With no `sharing.toml` target at all, `share targets` ends in `Skipped: No sharing target is configured` and `preview` and `push` fail with that message (`scope_no_match`); both add `help: add a [[misp]] block to .opentide/configurations/sharing.toml`.

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
