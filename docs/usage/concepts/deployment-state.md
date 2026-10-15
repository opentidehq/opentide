---
title: Deployment state
description: Where OpenTide keeps the vendor rule ids that Defender for Endpoint, SentinelOne and CrowdStrike assign, and why the files must be committed.
---

# Deployment state

Microsoft Defender for Endpoint, SentinelOne and CrowdStrike give every rule
OpenTide creates an id of their own. The next deploy has to update or delete the
remote rule by that id. OpenTide keeps it in a per-rule JSON file under
`.opentide/states/`, not in the rule YAML.

The normative definition is [`specs/deployment-state.md`](https://github.com/OpenTideHQ/specifications/blob/main/specs/deployment-state.md)
(`deployment.state::1.0`) in OpenTideHQ/specifications, accepted with RFC 0010.

## What lives under `.opentide/states/`

| Path | What it is | Commit it? |
|------|------------|------------|
| `.opentide/states/deployment/<uuid>.json` | Vendor rule id for one rule, per platform and tenant | **Yes.** Never gitignore this directory |
| `.opentide/states/sharing.jsonl` | Sharing cache ([`opentide share`](../../cli/share.md)) | No. Safe to delete |
| `.opentide/inflight/` | Preview overlay. Not part of `states/` | Unchanged |

`opentide setup repo` writes `.opentide/states/sharing.jsonl` to `.gitignore`.
Workspaces created by older releases ignore the whole `.opentide/states/`
directory: change that line before you deploy (see [Migration](../migration/index.md#vendor-rule-ids-move-to-deployment-state)).

## The shard

`<uuid>` is the rule's `metadata.uuid` in lowercase canonical form, and the
file's `object_uuid` is exactly that string. A rule that has never been
deployed to one of the three platforms has no file. Sentinel, Splunk,
HarfangLab and Carbon Black address rules by `metadata.uuid` or by title and
never get one.

```json
{
  "object_uuid": "00000000-0000-4000-8003-000000000010",
  "platforms": {
    "crowdstrike": {
      "falcon-prod": "c5e1b2a0e4c84f0a9d3b7e6a1c8f0d22"
    },
    "defender_for_endpoint": {
      "contoso": "12345",
      "fabrikam": "67890"
    }
  },
  "schema": "deployment.state::1.0"
}
```

- Tenant keys are the tenant `name` from `.opentide/configurations/platforms/<platform>.toml`, with surrounding spaces removed. A stored key that itself has surrounding spaces (`" contoso "`) is invalid. Renaming a tenant orphans its entry, and the next deploy creates a new remote rule.
- Only the canonical spelling is read. An uppercase, unhyphenated or `.JSON` file name, or a second file for the same rule, is `deployment_state_uuid_mismatch` and the rule is refused: a case-sensitive checkout would not find such a file, and deploy would create a second remote rule.
- An empty `platforms` map, or an empty map for one platform, reads as no binding. Writers never leave one behind.
- Ids are JSON strings. Defender and SentinelOne ids are canonical decimal integers (`12345`, no sign or leading zero). CrowdStrike ids are stored exactly as the API returned them.
- Keys are sorted, the indent is two spaces, and the file ends with one newline, so a deploy that touches one tenant changes one line in review.

## What deploy does with it

For each rule and tenant, before any HTTP call:

| Rule still has `rule_id`, `rule_id_bundle` or `rule_id::<tenant>` | Shard entry | Result |
|---|---|---|
| yes | any | `external_id_in_rule`. The rule is not deployed |
| no | present | Update (a disabled status is an update), or delete and remove the entry |
| no | absent | Create, then write the returned id into the shard |
| no | absent, status is a deletion or disablement | `external_id_missing` warning. Nothing is called |

A delete removes the tenant entry, then the platform when it has no tenants
left, then the file when it is empty.

The first row applies whatever platform is being deployed: a rule with a vendor id key on any block is left out of the whole deployment plan, `deploy --dry-run` and `validate query --live` included.

Refusals are per rule: the run continues with other rules, and exits `1` if any rule reported one of the error codes below. `external_id_missing` is a warning and does not fail the run.

| Code | Meaning |
|------|---------|
| `external_id_in_rule` | The rule still carries a vendor id key. Run `opentide deploy migrate-state` |
| `external_id_missing` | Warning. A deletion or disablement has no stored id for that tenant, so nothing is known to exist there and nothing is called. If a remote copy exists, remove it by hand |
| `deployment_state_ignored` | `.gitignore` hides `.opentide/states/deployment/`, so deploy refuses to create a rule. Updates and deletes that find an existing shard still run, with a warning |
| `deployment_state_write_failed` | The vendor created the rule but the shard could not be written. The message carries the id; add it to the shard by hand. The remote rule is not rolled back |
| `deployment_state_uuid_mismatch` | The shard's file name is not the lowercase canonical uuid, its `object_uuid` is not exactly its file name, or another file names the same rule. No create runs for that rule |
| `deployment_state_platform` | The shard names a platform that does not store vendor ids |
| `deployment_state_shape` | The shard is not valid `deployment.state::1.0`, for example a tenant key with surrounding spaces |

`opentide validate` reports the same `external_id_in_rule`. A full-workspace
run checks every `*.json` under `.opentide/states/deployment/`, including
shards whose rule has been deleted: shards outlive their rules, and an orphan
is still the only handle on its remote rule. A run narrowed with `--file`,
`--uuid` or `--type` checks the selected rules' shards. A missing shard is not
an error.

## Commit the shards

A deploy that creates a rule writes the shard in the working tree. If that file
is never committed, the next deploy from a clean checkout sees no id and
creates a second live rule beside the first. Commit `.opentide/states/deployment/`
together with the rules that produced it, including from CI.
