---
title: "RFC 0012, revision 2: the rule block (draft)"
description: "The revised text of specifications RFC 0012 for rule::2.0: one rule block shaped like the threat and objective bodies, one severity, one ATT&CK field and policy, an explicit objective and signals link, and a mechanical migration. Staged here until it replaces rfcs/0012 in opentidehq/specifications."
---

# RFC 0012: Rules should read like the other objects (revision 2)

- **RFC:** 0012
- **Title:** Rules should read like the other objects
- **Author:** opentide maintainers
- **Status:** draft, revision 2 (proposed to replace the 2026-10-19 text)
- **Created:** 2026-09-30
- **Revised:** 2026-11-26. Rebased on opentide 1.0 (the Rust core, thirteen platforms, `microsoft_defender`). Corrects the severity pin. Collapses the two severities into one. Renames `techniques` to `mitre_attack` and gives it one inheritance policy. Splits `detection_model` into `objective` and `signals`. Makes `status` required on every block. Tightens block `schema`. Specifies a text-preserving migration. Answers the four questions the first draft left open.
- **Issue:** [opentidehq/specifications#24](https://github.com/opentidehq/specifications/issues/24)
- **Implementation:** tracked in [rule-2.0](./rule-2.0.md). The earlier tracker, opentide#394, was closed: it described the Python code that 1.0 replaced.

This page holds the RFC's text while it is reviewed. Once it is accepted, the text replaces `rfcs/0012-rule-document-shape.md` in opentidehq/specifications, and this page links there.

## Summary

A threat file keeps its content in a `threat:` block, and an objective file keeps its content in an `objective:` block. A rule file has no such block. Its description, severity, techniques, objective link and response sit on the document root, and its detections sit under a `configurations:` wrapper. A legacy `platforms:` map can sit beside that wrapper.

`rule::2.0` puts the rule in a `rule:` block, shaped like the other two bodies. Each platform's detection is a key of that block. Platform payloads are unchanged. Status lives only on the platform block, which is where deploy already reads it. The rule has one severity, the one deploy sends. Its ATT&CK field has the name it has on threats and objectives, `mitre_attack`, and one inheritance policy. The link to an objective is named `objective`, and an optional `signals` list says which of its signals the rule implements.

`rule::1.0` and `rule::1.1` files keep their layout and keep working ([versioning 1.1](https://github.com/opentidehq/specifications/blob/main/specs/versioning.md)). Moving a file to 2.0 is one explicit command.

## Motivation

**Three shapes.** Authors and agents already know the pattern from the other two objects: name and metadata on the outside, the content in a block named after the object. Rules break that pattern.

**Two severities.** A 1.x rule has `severity` and `response.alert_severity`. Both take `alert_severity::1.0` values. Deploy sends `response.alert_severity` and ignores `severity`. MISP sharing reads the root `severity` for `threat_level_id`. Generated documentation shows `response.alert_severity` and falls back to `severity`. So one rule can be High in a tenant and Medium in MISP.

**Two status locations.** Deploy, promotion and the planner read `configurations.<platform>.status`, and opentide 1.0 requires that field on every block. The root `status` is read only by sharing's `rule_statuses` and by the MCP `deployment_status` tool, as a fallback when no enabled block has a status. The 1.0 model's own doc string calls it "read by no command".

**Three technique policies.** Sentinel, Defender and the platforms that use the shared policy send the block's own list when it has one, and otherwise the techniques inherited through `detection_model`. Those platforms never read the root `techniques`. Splunk correlation searches and Elastic merge the root `techniques` with the inherited ones. MISP reads the root `techniques` only. Threats and objectives call the same field `mitre_attack`.

**An ambiguous link.** `detection_model` holds either an objective UUID or a signal UUID. A signal reference implies its owning objective. Once signals can be reused ([RFC 0011](https://github.com/opentidehq/specifications/blob/main/rfcs/0011-signal-reuse.md)), a rule cannot say "this signal, as part of that objective". The field's name also suggests a data model.

**A word that means two things.** "Configuration" names the workspace's TOML under `.opentide/configurations/` and also the per-platform detection in a rule. The detection is part of the rule, and the document should say so.

## Detailed design

### The document

The envelope is the same as a threat's or an objective's: `name`, `metadata`, and optional `references`. The schema id is `rule::2.0`. `metadata.reviewed` keeps the meaning it has on `rule::1.1`. A `rule::2.0` file without it is unreviewed.

```yaml
name: LSASS memory read by an unsigned process
metadata:
  uuid: 6d1c8a52-3f0e-4c1b-9a77-2b8e5d4f1a90
  schema: rule::2.0
  version: 3
  created: "2026-01-12"
  modified: "2026-11-20"
  reviewed: "2026-11-20"
  tlp: amber
rule:
  description: |
    An unsigned process opens a handle to lsass.exe with VM_READ access.
  severity: High
  mitre_attack: [T1003.001]
  objective: 1f0c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5
  signals: [7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d]
  response:
    playbook: https://soc.example.net/playbooks/credential-dumping
    responders: SOC L2
  sentinel:
    enabled: true
    status: STAGING
    query: |
      DeviceEvents
      | where ActionType == "OpenProcessApiCall"
      | where FileName =~ "lsass.exe"
    scheduling:
      frequency: PT1H
      lookback: PT2H
    alert:
      title: LSASS memory read
      suppression: false
```

| Concern | `rule::1.0` / `rule::1.1` | `rule::2.0` |
|---|---|---|
| Body | document root | `rule` |
| Description | `description` | `rule.description` |
| Severity | `severity` (shown, shared to MISP) and `response.alert_severity` (deployed) | `rule.severity`, one value, `alert_severity::1.0` |
| ATT&CK | `techniques` | `rule.mitre_attack`, as on threats and objectives |
| Objective link | `detection_model`, an objective or a signal UUID | `rule.objective`, an objective UUID, and optional `rule.signals`, a list of signal UUIDs |
| Response | `response` (`alert_severity`, `playbook`, `responders`, `procedure`) | `rule.response` (`playbook`, `responders`, `procedure`) |
| Platform detection | `configurations.<platform>`, or legacy `platforms.<platform>` | `rule.<platform>` |
| Status | root `status` (sharing and MCP fallback) and `configurations.*.status` (deploy) | `rule.<platform>.status` only |
| Loader field | `file` (accepted from authors) | not part of the document |
| `metadata.reviewed` | `rule::1.1` only | optional |

### The `rule` block

| Field | Required | Default | Notes |
|---|---|---|---|
| `description` | yes | — | The narrative. |
| `severity` | no | `Informational` | `alert_severity::1.0`. This is the value every platform sends as its alert severity unless the block overrides it, and the value MISP maps to `threat_level_id`. |
| `mitre_attack` | no | `[]` | ATT&CK technique ids, `att&ck::1.2`. See [ATT&CK](#attck). |
| `objective` | no | — | UUID of the objective this rule implements. It names an objective only, never a signal. |
| `signals` | no | `[]` | UUIDs of signals the rule implements. Each MUST be in the effective signals of `objective`. A non-empty `signals` list requires `objective`. |
| `response` | no | — | `playbook`, `responders` and `procedure`, as on 1.x. There is no `alert_severity`. `responders` is free text, defaulted from `[deployment] default_responders`. |
| `<platform>` | no | — | One key per platform in the registry: `sentinel`, `microsoft_defender`, `splunk`, `sentinel_one`, `crowdstrike`, `harfanglab`, `carbon_black_cloud`, `elastic`, `sysdig`, `bitdefender`, `graylog`, `exabeam`, `google_secops`. |

Unknown keys MUST fail. The root of a `rule::2.0` file MUST NOT carry `description`, `status`, `severity`, `techniques`, `detection_model`, `objective`, `response`, `configurations`, `platforms` or `file`. A 1.x file is recognised by those keys, and the error names the 2.0 path, for example "`configurations` is not a `rule::2.0` key; platform blocks are keys of `rule`".

A platform identifier MUST NOT equal a field of the `rule` block. The registry enforces this, so adding a platform cannot shadow `severity` or `response`.

A rule with no platform key is a valid draft. It deploys once a block sets `enabled: true` and a status whose strategy deploys it.

### Platform blocks

The blocks move without changing. A Sentinel block is still `platform::sentinel::1.0`: `query`, `scheduling`, `alert` and the rest. This holds for every platform. A platform's own schema id evolves independently of the rule revision. A new platform is a new optional key, and it does not bump `rule::2.0`.

Two rules are tightened on `rule::2.0` only:

- **`status` is required on every block.** opentide 1.0 already requires it, because the deploy planner selects on it. The 1.x specs still call it optional, and that drift is closed here.
- **`schema`, when present, MUST be a registered identifier of the key's family**, `platform::<key>::<major>.<minor>`. The legacy identifiers that 1.x accepts (`sentinel::2.4`, `splunk::3.0`, `carbon_black_cloud::3.0`) are refused on 2.0, and the migration rewrites them. An omitted `schema` means the platform's newest registered revision, as today. This leaves room for a `platform::sentinel::2.0` block without a new rule revision.

Blocks carry no external ids ([RFC 0010](https://github.com/opentidehq/specifications/blob/main/rfcs/0010-deployment-external-ids.md)). Deployment-state shards are keyed by `metadata.uuid`, so moving a block does not touch `.opentide/states/deployment/`.

Rule-level fields that a platform spec reads move with the rule. Carbon Black's severity, Splunk's `alert.managedBy` and every alert severity read `rule.severity` and `rule.response.*` on 2.0. Report and saved-search descriptions read `rule.description`.

### Severity

`rule.severity` is the rule's only severity. A platform block that has its own severity field (for example an alert override) keeps it, and that field wins for that platform. Otherwise the platform sends `rule.severity`. Sharing maps `rule.severity` to MISP `threat_level_id`. Documentation shows it.

### ATT&CK

On a `rule::2.0` file, the techniques a platform sends, the techniques sharing publishes and the techniques coverage counts follow one policy:

1. A block's own technique list (for example `sentinel.alert.techniques`), when it is non-empty, for that platform.
2. Else `rule.mitre_attack`, when it is non-empty.
3. Else the techniques inherited from `rule.objective`: that objective's `mitre_attack`, else the techniques of its threats, as opentide resolves them today.

Explicit beats inherited, and the lists are never merged. A rule's techniques usually narrow its objective's, and merging would overclaim coverage. Duplicates are removed and order is kept.

### Objective and signals

`rule.objective` is direct coverage of one objective. `rule.signals` narrows that coverage:

| `objective` | `signals` | The rule covers |
|---|---|---|
| unset | empty | nothing (a draft) |
| set | empty | the objective, as `detection_model: <objective>` does on 1.x |
| set | non-empty | those signals of the objective, and through them the objective, partially |
| unset | non-empty | invalid: `rule_signals_without_objective` |

Each signal MUST be in `effective_signals(objective)`. That set is the objective's definitions and, once `objective::1.1` ships, its resolved `reuse` bindings. Otherwise the error is `rule_signal_not_in_objective`. An unknown objective or signal is `invalid_ref`, as today.

Indirect coverage ([RFC 0011](https://github.com/opentidehq/specifications/blob/main/rfcs/0011-signal-reuse.md)) starts from the listed signals, or from all of the objective's effective signals when `signals` is empty. That is the set 1.x derives from a `detection_model`.

Completion offers objectives for `objective`, and only that objective's effective signals for `signals`, labelled `{objective name}::{signal name}`. The `objective` model vocabulary keeps listing signals for 1.x `detection_model` only.

### Status outside deploy

A `rule::2.0` rule matches a sharing block's `rule_statuses` when at least one enabled platform block has a status in the list. A rule with no enabled block matches nothing. There is no root fallback, because there is no root status. Blocks for platforms the workspace has not enabled count, as on 1.x: sharing describes content, and deploy describes targets. The MCP `deployment_status` tool reads block statuses only. Documentation shows each block's status.

On 1.x files these consumers keep the root-status fallback ([sharing.md](https://github.com/opentidehq/specifications/blob/main/specs/sharing.md) 1.2).

### Pins

```toml
["rule::2.0"]
"metadata.tlp" = "tlp::1.0"
"rule.severity" = "alert_severity::1.0"
"rule.mitre_attack" = "att&ck::1.2"
```

`rule.response.responders` has no pin. `rule.objective` binds the `objective` model vocabulary restricted to objectives. `rule.signals` binds the `signal` model vocabulary ([metaschema-keywords.md](https://github.com/opentidehq/specifications/blob/main/specs/metaschema-keywords.md)) restricted to the chosen objective's effective set.

### Migrating a file

`opentide migrate rule` moves `rule::1.0` and `rule::1.1` files to `rule::2.0`. It is a dry run unless `--apply` is given. Opening, validating or deploying a 1.x file never rewrites it.

| 1.x | 2.0 |
|---|---|
| `description`, `response` | moved under `rule` |
| `techniques` | `rule.mitre_attack` (omitted when empty) |
| `response.alert_severity` | `rule.severity`. When the rule has no `response`, the root `severity` is used. If both are set and differ, the deployed value (`response.alert_severity`) wins, and the report names the dropped root value, because MISP's threat level changes. |
| `detection_model` naming an objective | `rule.objective` |
| `detection_model` naming a signal | `rule.objective` set to the signal's owning objective, and `rule.signals: [<signal>]` |
| `detection_model` naming nothing in the workspace | the file is left unchanged, and the report says why (exit 2, `needs_human_decision`) |
| `configurations.<platform>`, and `platforms.<platform>` when it is the only copy | `rule.<platform>` |
| a legacy block `schema` (`sentinel::2.4`) | `platform::sentinel::1.0` |
| root `status` | removed. A block without a status gets it, which cannot happen in a file that opentide 1.0 validates. When the rule has no enabled block, the report says the rule stops matching `rule_statuses`. |
| `file` | removed and reported |
| `metadata.reviewed` | kept. A `rule::1.0` file gets none, so it stays unreviewed. |
| `metadata.schema` | `rule::2.0` |
| `metadata.version`, `metadata.modified` | unchanged |

The migration refuses a file whose `configurations` and `platforms` both declare a platform, a file with an unknown platform key, and a file that fails validation as declared. Fix the file first. Migration never turns an invalid 1.x file into a different invalid 2.0 file.

The rewrite preserves text. The root fields move under `rule:` with their comments and are indented by two spaces. A block scalar keeps its content because every line gains the same indentation. Platform blocks keep their lines exactly: they sat at indentation 2 under `configurations:` and sit at indentation 2 under `rule:`. Keys are renamed in place. Each rewritten file is parsed again and compared with the intended document, and a file that differs is left unchanged. BOM, line endings, quoting and key order are kept, as `migrate vocab-scope` keeps them.

Migration is forward-only and idempotent. A `rule::2.0` file is reported as already migrated.

### Other specs that name rule fields

- `specs/metadata.md`: `metadata.reviewed` is defined for `rule::1.1` and `rule::2.0`.
- `specs/sharing.md` and `specs/sharing/misp-1.0.md`: the status match above. The relation source is `rule.objective` plus `rule.signals` on 2.0 and `detection_model` on 1.x. `threat_level_id` comes from `rule.severity`. Techniques follow the ATT&CK policy.
- `specs/platforms/index.md`: a block lives at `configurations.<platform>` on 1.x and at `rule.<platform>` on 2.0. The shared-block table marks `status` required, which matches the implementation.
- `specs/deployment.md`: "Promotion rewrites the `status` values inside a rule's platform blocks" (`configurations.*` on 1.x, `rule.*` on 2.0).
- `specs/objects/objective-1.0.md` and `objective-1.1.md`: the top-level `composition` was dropped by opentide 1.0 and is now an unknown key. The specs still require it. Fix that drift in the same change, because this RFC is about the objects reading alike.
- [RFC 0011](https://github.com/opentidehq/specifications/blob/main/rfcs/0011-signal-reuse.md): a `rule::2.0` file's direct coverage is `rule.objective`, narrowed by `rule.signals`.

### What lands with acceptance

- `specs/objects/rule-2.0.md`, history notes on `rule-1.0.md` and `rule-1.1.md` (still normative), and the related spec edits above.
- A `rule::2.0` section in `schemas/pins/rule.toml`.
- Valid fixtures: a full rule, a draft with no block, a rule with `signals`. Invalid fixtures: a leftover `configurations`, a root `status`, `severity` on the root, `response.alert_severity`, `techniques`, `detection_model`, a block without `status`, a legacy block `schema`, `signals` without `objective`, and a signal outside the objective.
- Migration fixtures: pairs of 1.0 and 1.1 inputs with their 2.0 outputs, including comments, block scalars, a signal-valued `detection_model` and a severity conflict.
- `SPECS.md` and `CHANGELOG.md`.

## Drawbacks

Two layouts will exist until people migrate. Every consumer reads both, which the versioning spec already requires. The implementation reads one in-memory shape (2.0) and translates paths back for 1.x diagnostics ([rule-2.0](./rule-2.0.md#strategy)).

A rule that relied on the root `severity` for its MISP threat level changes level when migrated. The migration reports each such rule.

Splunk correlation searches and Elastic rules that set both root `techniques` and an objective sent the union on 1.x. On 2.0 they send `mitre_attack` alone. Each such rule shows up in the dry run's payload diff.

## Alternatives

- **Rename `configurations` only.** Rules stay the odd object, and the two severities and three technique policies stay.
- **Nest blocks under `rule.platforms`.** This adds a level and reuses the name of the legacy key. The flat form puts the Sentinel rule at `rule.sentinel`, which is what it is.
- **Keep a rule-level `status` that blocks inherit.** Fewer lines, but two sources of truth again. Promotion would have to choose which one to rewrite.
- **Keep `detection_model` polymorphic under a new name (`rule.implements`).** Smaller migration, but it cannot express a reused signal in the context of the objective that reuses it, and completion cannot narrow it.
- **Keep `techniques`.** Clearer alone, but it misaligns the three objects the RFC sets out to align.
- **Edit `rule::1.1` in place.** Every existing file would stop validating.

## Resolved questions (from the first draft)

1. **`opentide new` follows the newest revision.** It writes `rule::2.0` once that revision is registered, and so do `extract` and the MCP template. The registry is not flipped until every consumer reads 2.0.
2. **Sharing matches any enabled block**, and blocks for platforms the workspace has not enabled count.
3. **The link is `objective` plus `signals`**, not one polymorphic field.
4. **1.x is "superseded", not "deprecated", in the release that ships 2.0.** `validate` adds a `rule_revision_superseded` hint, not a warning, so CI does not break. 1.x keeps validating and deploying indefinitely. Removing a revision needs a versioning-spec change, and none is proposed.

## Unresolved questions

- **`enabled` and the status strategies overlap.** `enabled: false`, a status whose strategy is `INERT`, and a platform disabled in the workspace all keep a block from deploying. They differ in whether sharing and documentation see the block. This RFC keeps `enabled` because the blocks do not change. A future platform-block revision could drop it in favour of the status strategy.
- **Should `metadata.reviewed` extend to threats and objectives?** Out of scope here. Note it for the next threat and objective revisions, together with the root `criticality` on threats.

## References

- [opentidehq/specifications#24](https://github.com/opentidehq/specifications/issues/24)
- [specs/versioning.md](https://github.com/opentidehq/specifications/blob/main/specs/versioning.md) 1.1
- [RFC 0008](https://github.com/opentidehq/specifications/blob/main/rfcs/0008-rule-reviewed-date.md), [RFC 0010](https://github.com/opentidehq/specifications/blob/main/rfcs/0010-deployment-external-ids.md), [RFC 0011](https://github.com/opentidehq/specifications/blob/main/rfcs/0011-signal-reuse.md), [RFC 0021](https://github.com/opentidehq/specifications/blob/main/rfcs/0021-defender-graph-beta-detection-rules.md)
- opentide [ADR 0009](./adr/0009-revision-registry.md), the revision registry
