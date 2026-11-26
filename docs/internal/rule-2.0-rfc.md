---
title: "RFC 0012, revision 3: the rule block (draft)"
description: "The revised text of specifications RFC 0012 for rule::2.0: an envelope root, one rule block with description, signals, mitre_attack, response and searches, and platform blocks that each carry their own status and severity. Staged here until it replaces rfcs/0012 in opentidehq/specifications."
---

# RFC 0012: Rules should read like the other objects (revision 3)

- **RFC:** 0012
- **Title:** Rules should read like the other objects
- **Author:** opentide maintainers
- **Status:** draft, revision 3 (proposed to replace the 2026-10-19 text)
- **Created:** 2026-09-30
- **Revised:** 2026-11-26 (revision 2, then revision 3 after maintainer review). Rebased on opentide 1.0 (the Rust core, thirteen platforms). Revision 3:
  - The root holds the envelope only.
  - Severity moves to each platform block.
  - The objective link becomes one `signals` list, which can name objectives or signals across objectives.
  - `techniques` becomes `mitre_attack`.
  - `response` is redesigned, and hunts become first-class `searches`.
  - The platform block's shared fields are defined once, as the block envelope.
- **Issue:** [opentidehq/specifications#24](https://github.com/opentidehq/specifications/issues/24)
- **Implementation:** [rule-2.0](./rule-2.0.md)

This page holds the RFC's text while it is reviewed. Once accepted, it replaces `rfcs/0012-rule-document-shape.md` in opentidehq/specifications.

## Summary

A threat file keeps its content in a `threat:` block, and an objective file keeps its content in an `objective:` block. A rule file has neither. Its content is spread over the root, a `configurations:` wrapper, and a `response.procedure` tree that mixes alert severity, team, analysis prose and hunt queries.

A `rule::2.0` file is an envelope (`name`, `metadata`, `references`) plus one `rule:` block. The block holds what the rule is (`description`, `signals`, `mitre_attack`), how an analyst handles it (`response`, `searches`), and one key per platform it is implemented on. Each platform block carries its own operational state: `enabled`, `status` and `severity`. Nothing about deployment sits at the rule level.

`rule::1.0` and `rule::1.1` files keep their layout and keep working ([versioning 1.1](https://github.com/opentidehq/specifications/blob/main/specs/versioning.md)). One explicit command moves a file to 2.0.

## Motivation

**Three shapes.** Threats and objectives put the name and metadata outside, and the content in a block named after the object. Rules do not.

**Operational state in two places.** Deploy reads `configurations.<platform>.status`, and opentide 1.0 requires it on every block. A root `status` also exists, and only sharing and one MCP tool read it, as a fallback. Severity has the same problem:

- Ten of the thirteen platform blocks have their own severity or priority field: Sentinel and Defender `alert.severity`, SentinelOne and CrowdStrike `details.severity`, and `severity` or `priority` on Elastic, Sysdig, Bitdefender, Graylog, Exabeam and Google SecOps. When it is unset, deploy derives it from `response.alert_severity`.
- Splunk, Carbon Black Cloud and HarfangLab use `response.alert_severity` directly.
- MISP's threat level reads a third value, the root `severity`.

A rule is not "High". Its Sentinel analytics rule might be High while its noisier Splunk search is Low.

**Three technique policies.** Most platforms send the block's own technique list, else the techniques inherited through `detection_model`, and never read the root `techniques`. Splunk correlation searches and Elastic merge the root list with the inherited one. MISP sends the root list only. Threats and objectives name the field `mitre_attack`.

**One link, one target.** `detection_model` holds a single UUID, either an objective or a signal. A rule that implements two signals, possibly of two objectives, cannot say so.

**A response block that is really four things.** `response` holds the alert severity (deployment), the responders (routing), a playbook link, and a `procedure` with analysis prose, containment prose and hunt `searches`. A search names its target in free text (`system: Microsoft Sentinel`), which the documentation renderer matches loosely to guess a language. Searches cannot be run by name, and there is no place for known false positives or blind spots. The Elastic and HarfangLab blocks each grew their own `false_positives` for that reason.

**"Configuration" means two things.** It names the workspace's TOML under `.opentide/configurations/` and also the per-platform detection inside a rule.

## The anatomy of a rule

| Part | Question it answers | 1.x | 2.0 |
|---|---|---|---|
| Identity | Which object is this? | `name`, `metadata`, `references` | the same, on the root |
| Intent | What does it detect, and why? | `description`, `techniques`, `detection_model` | `rule.description`, `rule.mitre_attack`, `rule.signals` |
| Knowledge | When is it wrong, and what can it not see? | none (two platforms improvise) | `rule.false_positives`, `rule.blind_spots` |
| Response | Who handles it, and how? | `response.*`, `response.procedure.*` | `rule.response` |
| Searches | What else should the analyst run? | `response.procedure.searches` | `rule.searches` |
| Implementations | How is it expressed on each platform? | `configurations.<platform>` | `rule.<platform>` |
| Operation | Is it live, where, and how loud? | root `status`, root `severity`, `response.alert_severity`, block `status` | block envelope: `enabled`, `status`, `severity`, `tenants`, `flags` |

The root keeps identity only. Everything that describes the detection lives in `rule:`. Everything that describes one platform's deployment lives in that platform's block.

## Detailed design

### The document

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
  contributors: [j.doe]
references:
  public:
    1: https://attack.mitre.org/techniques/T1003/001/
rule:
  description: |
    An unsigned process opens a handle to lsass.exe with VM_READ access.
  signals:
    - 7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d   # a signal of the credential-access objective
    - 2c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f   # a signal of the defence-evasion objective
  mitre_attack: [T1003.001]
  false_positives:
    - Endpoint agents and backup software that read LSASS memory.
  blind_spots: |
    Handles opened through a signed, abused driver are not seen.
  response:
    responders: soc-l2
    playbook: https://soc.example.net/playbooks/credential-dumping
    triage: |
      Check the process signer and parent. A known agent is a false positive.
    containment: |
      Isolate the host and reset credentials of accounts logged on to it.
  searches:
    - id: same-binary-elsewhere
      kind: pivot
      description: Other hosts that ran the same binary
      platform: microsoft_defender
      query: |
        DeviceProcessEvents
        | where SHA256 == "<sha256>"
        | summarize by DeviceName
  sentinel:
    enabled: true
    status: STAGING
    severity: High
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
  splunk:
    enabled: true
    status: DEVELOPMENT
    severity: Medium
    query: |
      index=edr EventCode=10 TargetImage="*lsass.exe"
```

### The root

The root of a `rule::2.0` file holds `name`, `metadata` and optional `references`, and nothing else.

| Key | Kept because |
|---|---|
| `name` | Every object names itself the same way. Deploy uses it as the default display name, and lint checks file names against it. |
| `metadata` | Identity, revision, dates, TLP and authorship, shared by all objects. |
| `references` | Provenance of the object, the same `ObjectReferences` on threats and objectives. Sharing and exports read it in one place for every family. |

The root MUST NOT carry `description`, `status`, `severity`, `techniques`, `mitre_attack`, `detection_model`, `signals`, `response`, `configurations`, `platforms` or `file`. Those keys are how a 1.x file is recognised. The error names the 2.0 path, for example "`configurations` is not a `rule::2.0` key; platform blocks are keys of `rule`".

### The `rule` block

| Field | Required | Default | Meaning |
|---|---|---|---|
| `description` | yes | — | What the rule detects and how. Markdown. |
| `signals` | no | `[]` | UUIDs of the objectives and signals the rule implements. See [Signals](#signals). |
| `mitre_attack` | no | `[]` | ATT&CK technique ids, `att&ck::1.2`, as on threats and objectives. See [ATT&CK](#attck). |
| `false_positives` | no | `[]` | Known benign causes, one per item. |
| `blind_spots` | no | — | What the rule cannot see, and what it assumes. Markdown. |
| `response` | no | — | Who handles an alert, and how. See [Response](#response). |
| `searches` | no | `[]` | Named queries an analyst or agent runs. See [Searches](#searches). |
| `<platform>` | no | — | One key per platform in the registry. See [Platform blocks](#platform-blocks). |

Unknown keys MUST fail. A platform identifier MUST NOT equal a field of the `rule` block, and the registry enforces that.

A rule with no platform key is a valid draft.

### Signals

`rule.signals` is a list of UUIDs. Each MUST name an objective or a signal defined under an objective in the workspace. Otherwise the error is `invalid_ref`, as for `detection_model` today. An objective stands for all of its effective signals. The list MAY name signals of different objectives.

| Listed | The rule covers |
|---|---|
| nothing | nothing (a draft) |
| an objective | that objective, fully (as `detection_model: <objective>` on 1.x) |
| a signal | that signal, and its owning objective partially (as `detection_model: <signal>` on 1.x) |
| several | the union. Each objective reached only through some of its signals is covered partially, and reports list the via-signal UUIDs. |

A UUID listed twice is `duplicate_signal`. A signal listed beside its own objective adds nothing and gets the hint `signal_covered_by_objective`. With signal reuse ([RFC 0011](https://github.com/opentidehq/specifications/blob/main/rfcs/0011-signal-reuse.md)), indirect coverage starts from the listed signals, plus every effective signal of each listed objective.

Completion offers objectives and signals together, as the `objective` model vocabulary does for `detection_model` today. A signal is labelled `{objective name}::{signal name}`.

### ATT&CK

The techniques a platform sends, sharing publishes and coverage counts follow one policy:

1. A block's own technique list (for example `sentinel.alert.techniques`), when it is non-empty, for that platform.
2. Else `rule.mitre_attack`, when it is non-empty.
3. Else the techniques inherited through `rule.signals`: for each listed objective, and for each listed signal's owning objective, its `mitre_attack`, else its threats' techniques. Duplicates are removed and the order of `signals` is kept.

Explicit beats inherited, and the lists are never merged. A rule usually detects a narrower set of techniques than its objectives, so merging would overclaim coverage.

### Response

`rule.response` says who handles an alert and what they do. Severity is gone from it, because each platform block now carries its own, and the `procedure` level is flattened.

| Field | Required | Meaning | 1.x source |
|---|---|---|---|
| `responders` | no | The team that handles the alert: a `[[responders]]` name from `deployment.toml`, defaulted from `[deployment] default_responders`. | `response.responders` |
| `playbook` | no | Link or identifier of the SOAR playbook. | `response.playbook` |
| `triage` | no | Markdown: how to decide whether an alert is real. Elastic sends it as the investigation guide (Kibana `note`) unless the block sets `guide.investigation`. | `response.procedure.analysis` |
| `containment` | no | Markdown: what to do once it is real. | `response.procedure.containment` |

`false_positives` and `blind_spots` sit on `rule`, not under `response`. They describe the detection and serve tuning and coverage review as much as triage. A platform block's own `false_positives` (Elastic, HarfangLab) wins for that platform. Otherwise those platforms send `rule.false_positives`.

### Searches

A search is a query that is not the detection: a pivot an analyst runs on an alert, or a hunt run without one. On 1.x, searches were prose-adjacent entries under `response.procedure`. On 2.0 they are first-class and can be run by name.

```yaml
searches:
  - id: same-binary-elsewhere
    kind: pivot
    description: Other hosts that ran the same binary
    platform: microsoft_defender
    query: |
      DeviceProcessEvents | where SHA256 == "<sha256>"
  - id: lsass-readers-weekly
    kind: hunt
    description: Every process that read LSASS memory, for baseline review
    platform: elastic
    language: esql
    query: |
      FROM logs-endpoint.events.api-*
      | WHERE process.Ext.api.name == "ReadProcessMemory"
```

| Field | Required | Meaning | 1.x source |
|---|---|---|---|
| `id` | yes | Unique in the rule. Lowercase letters, digits and `-`. `opentide query --rule <uuid> --search <id>` and the MCP `run_query` tool run it. | none (new) |
| `kind` | yes | `pivot` (run on an alert) or `hunt` (run without one), from the `search.kind::1.0` vocabulary. | none (new; migration writes `pivot`) |
| `description` | yes | What the search shows. | `purpose` |
| `platform` | yes | A platform identifier from the registry. | `system` (free text) |
| `language` | no | Required when the platform has several languages (Elastic: `kuery`, `lucene`, `eql`, `esql`). MUST NOT be set otherwise. | `language` |
| `query` | yes | The query. `opentide validate` checks it offline with the platform's engine, as today. | `query` |

`platform` is typed, so validation, highlighting, documentation and `opentide query` know the language without guessing from free text. A 1.x `system` that names no platform (`SIEM`, `EDR console`) cannot be migrated mechanically, and the migration reports it.

Searches take no parameters in this revision. A later additive field (`parameters`, with typed placeholders the analysis engine substitutes before parsing) can add them without a new revision. The `<sha256>` above is prose.

### Platform blocks

A platform block has two parts:

- **The envelope:** the fields every platform shares, defined by this rule revision.
- **The payload:** the platform's own fields, defined by its platform schema (`platform::sentinel::1.0` and the others), unchanged.

| Envelope field | Required | Meaning | 1.x |
|---|---|---|---|
| `enabled` | no, `false` | Whether this block takes part in deployment. | same |
| `status` | yes | A deployment status from `deployment.toml`. | same. Required in opentide 1.0, and the 1.x spec catches up. |
| `severity` | yes | `alert_severity::1.0`: `Informational`, `Low`, `Medium`, `High`, `Critical`. The severity of this platform's alerts. | `response.alert_severity`, shared by every block |
| `tenants` | no | Tenants this block deploys to. Default: every tenant of the platform that is not `manual` and accepts the status's strategy. | same |
| `flags` | no | Labels that `[[modifiers]]` conditions in platform configuration match. | same |
| `name` | no | Display name on this platform. Default: the root `name`. | same |
| `schema` | no | The payload's schema: `platform::<key>::<major>.<minor>`, a registered revision of that key's family. Default: the newest. Legacy identifiers (`sentinel::2.4`) are refused. | legacy ids accepted |

The 1.x envelope's `contributors` is not part of 2.0. Authorship is `metadata.author` and `metadata.contributors`, and CrowdStrike's author list reads them.

**Severity on the block.** `severity` is the block's severity on opentide's scale. A payload field that carries the vendor's own severity or priority stays valid and wins for that vendor. Examples are Sentinel's `alert.severity`, Falco's eight-level `priority`, Elastic's severity overrides and Google SecOps `priority`. When unset, deploy derives the vendor's field from the envelope `severity`, with the mapping each platform spec already defines for `response.alert_severity`. Splunk, Carbon Black Cloud and HarfangLab read `severity` directly.

**The rule's severity.** Sharing, documentation and catalogue sorting need one value. It is derived, never authored: the highest `severity` among enabled blocks, or `Informational` when no block is enabled. MISP `threat_level_id` maps it.

A new platform is a new optional key and does not bump `rule::2.0`. A platform's payload schema evolves on its own: the envelope belongs to the rule revision, so a payload revision never has to restate it.

Blocks carry no external ids ([RFC 0010](https://github.com/opentidehq/specifications/blob/main/rfcs/0010-deployment-external-ids.md)). Deployment-state shards are keyed by `metadata.uuid`, so moving a block does not touch `.opentide/states/deployment/`.

### Status outside deploy

A `rule::2.0` rule matches a sharing block's `rule_statuses` when at least one enabled platform block has a status in the list. Blocks for platforms the workspace has not enabled count. A rule with no enabled block matches nothing. The MCP `deployment_status` tool reads block statuses only. 1.x files keep the root-status fallback ([sharing.md](https://github.com/opentidehq/specifications/blob/main/specs/sharing.md) 1.2).

### Pins

```toml
["rule::2.0"]
"metadata.tlp" = "tlp::1.0"
"rule.mitre_attack" = "att&ck::1.2"
"rule.searches.kind" = "search.kind::1.0"
"rule.<platform>.severity" = "alert_severity::1.0"   # one row per platform in the file
```

`rule.signals` binds the `objective` model vocabulary (objectives and every signal defined under one). `rule.response.responders` binds `tide.config.responders`, as on 1.x.

### Migrating a file

`opentide migrate rule` moves `rule::1.0` and `rule::1.1` files to `rule::2.0`. It is a dry run unless `--apply` is given. Opening, validating or deploying a 1.x file never rewrites it.

| 1.x | 2.0 | Needs a person when |
|---|---|---|
| `description` | `rule.description` | never |
| `detection_model: X` | `rule.signals: [X]` | never |
| `techniques` | `rule.mitre_attack` (omitted when empty) | never |
| `response.alert_severity` (or root `severity` without a `response`, or `Informational`) | `severity` on every platform block | a root `severity` that differs from `response.alert_severity` is reported: MISP's threat level changes |
| `response.responders`, `response.playbook` | `rule.response.responders`, `rule.response.playbook` | never |
| `response.procedure.analysis`, `.containment` | `rule.response.triage`, `rule.response.containment` | never |
| `response.procedure.searches[i]` | `rule.searches[i]`: `id` from `purpose` (slugged, made unique), `kind: pivot`, `description` = `purpose`, `platform` from `system` | a `system` that names no platform: the file is left unchanged (exit 2, `needs_human_decision`) |
| `configurations.<p>`, or `platforms.<p>` when it is the only copy | `rule.<p>` | the same platform in both: refused |
| a block's `contributors` | merged into `metadata.contributors` | never (reported) |
| a legacy block `schema` | `platform::<p>::1.0` | never |
| root `status` | removed | a rule with no enabled block is reported: it stops matching `rule_statuses` |
| `file` | removed | never (reported) |
| `metadata.reviewed`, `version`, `modified` | unchanged | never |

The migration refuses a file that fails validation as declared. It never turns an invalid 1.x file into a different invalid 2.0 file.

The rewrite preserves text:

- Root entries move under an inserted `rule:` with two more spaces of indentation, and their comments move with them. A block scalar keeps its content, because every line gains the same indentation.
- Platform blocks keep their lines: they sat at indentation 2 under `configurations:` and sit at indentation 2 under `rule:`. The `severity` line is inserted after `status`.
- Keys are renamed in place.
- Each rewritten file is parsed again and compared with the intended document. A file that differs is left unchanged.
- BOM, line endings, quoting and key order are kept, as `migrate vocab-scope` keeps them.

Migration is forward-only and idempotent.

### Other specs that name rule fields

- `specs/metadata.md`: `metadata.reviewed` is defined for `rule::1.1` and `rule::2.0`.
- `specs/platforms/index.md`: the block envelope moves here from each platform's shared-field table for 2.0, and a block lives at `rule.<platform>`. Each platform spec's severity section names the envelope `severity` as the default for its native field.
- `specs/sharing.md`, `specs/sharing/misp-1.0.md`:
  - the status match above
  - relations from `rule.signals`
  - `threat_level_id` from the derived rule severity
  - techniques by the ATT&CK policy
- `specs/deployment.md`: promotion rewrites block statuses (`configurations.*` on 1.x, `rule.*` on 2.0).
- `specs/vocabularies`: a new `search.kind::1.0` with `pivot` and `hunt`.
- `specs/objects/objective-1.0.md` and `objective-1.1.md`: drop the top-level `composition` that opentide 1.0 already rejects. That fixes spec drift in the same change, because this RFC is about objects reading alike.
- [RFC 0011](https://github.com/opentidehq/specifications/blob/main/rfcs/0011-signal-reuse.md): direct coverage of a `rule::2.0` file is `rule.signals`.

### What lands with acceptance

- `specs/objects/rule-2.0.md`, history notes on `rule-1.0.md` and `rule-1.1.md` (still normative), and the related spec edits above.
- `schemas/pins/rule.toml` section, `search.kind::1.0`.
- Valid fixtures:
  - a full rule
  - a draft
  - signals across two objectives
  - an Elastic search with `language`
- Invalid fixtures:
  - each root key a 1.x file has
  - a block without `status` or `severity`
  - `response.alert_severity`
  - a block `contributors`
  - a legacy block `schema`
  - a search with an unknown `platform`, a missing `id`, or a duplicate `id`
  - `language` on a single-language platform
- Migration fixtures: 1.0 and 1.1 inputs with their 2.0 outputs. They cover comments, block scalars, a severity conflict, searches, legacy `platforms`, and a `system` that needs a person.
- `SPECS.md` and `CHANGELOG.md`.

## Drawbacks

Two layouts exist until people migrate. Every consumer reads both, as the versioning spec requires. The implementation reads both through one seam ([rule-2.0](./rule-2.0.md#strategy)).

`severity` is written once per block instead of once per rule. A rule on three platforms says it three times. That cost is the point: the three platforms can then disagree on purpose.

A rule that relied on the root `severity` for its MISP threat level, or on Splunk's or Elastic's merge of techniques, changes payload when migrated. The migration report lists each one.

## Alternatives

- **Rename `configurations` only.** Rules stay the odd object, and severity, status and searches stay where they are.
- **One rule-level severity that blocks override.** Fewer lines, but two sources of truth again, which is the problem this RFC removes for status.
- **Only the vendors' native severity fields, with no envelope `severity`.** No new key, but Splunk, Carbon Black and HarfangLab would need new payload fields. Sharing and documentation would need an inverse mapping from thirteen vendor scales.
- **`objective` plus `signals` fields** (revision 2 of this RFC). Explicit, but it cannot link a rule to signals of several objectives, and it is more than authors need.
- **Nest blocks under `rule.platforms`.** An extra level, and it reuses the name of the legacy key.
- **Keep searches under `response`.** Hunts are not a response to an alert. Pivots are, but both are queries with the same shape and the same runner.

## Resolved questions

1. **`opentide new`, `extract` and the MCP rule template follow the newest revision.** The registry is not flipped until every consumer reads 2.0.
2. **Sharing matches any enabled block,** including blocks for platforms the workspace has not enabled.
3. **The link is one `signals` list** that names objectives or signals, across objectives (maintainer review, 2026-11-26).
4. **`techniques` becomes `mitre_attack`,** and it lives in `rule:`, not on the root (maintainer review).
5. **`enabled` stays on blocks** (maintainer review). It is independent of the status strategy: a block can be disabled without losing its status.
6. **Severity belongs to each platform block** (maintainer review). The rule's severity is derived.
7. **1.x is "superseded", not "deprecated",** in the release that ships 2.0. `validate` adds a `rule_revision_superseded` hint. 1.x keeps validating and deploying.

## Unresolved questions

- **Search parameters.** Should 2.0 ship a `parameters` field now, with placeholders the engine substitutes before parsing, or add it later?
- **`metadata.reviewed` on threats and objectives,** and the root `criticality` on threats: for their next revisions, not this one.

## References

- [opentidehq/specifications#24](https://github.com/opentidehq/specifications/issues/24)
- [specs/versioning.md](https://github.com/opentidehq/specifications/blob/main/specs/versioning.md) 1.1
- [RFC 0008](https://github.com/opentidehq/specifications/blob/main/rfcs/0008-rule-reviewed-date.md), [RFC 0010](https://github.com/opentidehq/specifications/blob/main/rfcs/0010-deployment-external-ids.md), [RFC 0011](https://github.com/opentidehq/specifications/blob/main/rfcs/0011-signal-reuse.md), [RFC 0021](https://github.com/opentidehq/specifications/blob/main/rfcs/0021-defender-graph-beta-detection-rules.md)
- [Palantir's Alerting and Detection Strategy framework](https://github.com/palantir/alerting-detection-strategy-framework), whose blind spots, false positives and response sections informed `rule.false_positives`, `rule.blind_spots` and `rule.response`
- opentide [ADR 0009](./adr/0009-revision-registry.md), the revision registry
