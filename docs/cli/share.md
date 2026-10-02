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
| `--delete` | retract | Delete the remote event |
| `--yes` | retract | Required with `--delete` |

Filters only narrow the selection. An unknown `--target`, a disabled block named by `--target`, or no enabled block is a preflight failure. `max_tlp` is the ceiling: `red` shares TLP:RED, and there is no `--allow-tlp-red`.

`--changed` uses the same commit range as `opentide deploy --plan PRODUCTION`. It keeps `.yaml` and `.yml` files that sit directly in the configured threat, objective, and rule directories. Added and modified files are included. Deletions are ignored, and a deletion does not retract. It runs on a push to the default branch in GitHub Actions, GitLab CI, or Azure Pipelines. On a pull request, or outside those three, it is a preflight failure and makes no request. An empty diff exits `0`. With no `--target` and no enabled block, `--changed` also exits `0`. An unknown or disabled `--target` is still `scope_no_match`.

```bash
opentide share push --changed
```

`push` and `preview` validate each object that passes the type, status, and TLP filters. `sharing-config` runs as part of loading `sharing.toml`. A literal API key is a warning and is replaced with `[REDACTED]` if it would otherwise appear.

## State

Successful creates, updates, and retractions are recorded in `.opentide/states/sharing.jsonl`. Skips and failures leave the file unchanged. `preview` writes nothing. Setup gitignores `.opentide/states/`.

## Exit codes

Share uses two codes in addition to the [global exit codes](./exit-codes.md):

| Code | Meaning |
|-----:|---------|
| `0` | No object failed. Skips are not failures, so a run that only skips exits `0` |
| `1` | Preflight failure, or at least one object failed for a reason other than authentication or connectivity, and nothing succeeded |
| `2` | Every object failure is authentication or connectivity, and nothing succeeded |
| `3` | At least one object succeeded and at least one failed |

With `--json`, the document includes `records`: one entry per object UUID and block, with `action`, `reason` on skips and failures, and `remote_event_id` when MISP assigned one.
