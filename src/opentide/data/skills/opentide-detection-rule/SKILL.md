---
name: opentide-detection-rule
description: Authors OpenTide Detection Rule (MDR) YAML -- descriptions, response metadata, playbook hooks, analytic references -- and wires platform-specific configurations (Sentinel KQL, SPL, Defender advanced hunting, Falcon queries, SentinelOne rules, CBC watchlists, HarfangLab content) keyed per CoreTide deployment manifests. Covers structured description patterns, response procedure authoring, per-platform configuration schemas (sentinel, splunk, defender_for_endpoint, carbon_black_cloud), entity/risk mapping, exclusion discipline, and anti-patterns distilled from production corpora. Use when producing deployable artefacts or updating existing rules under Detection Rules folders.
---

# OpenTide Detection Rule (MDR)

An MDR is the **deployable artefact** — the detection rule that runs on a specific platform. It implements a DOM signal and carries the response metadata that guides analysts when the rule fires.

---

## Preconditions

1. Hydrate **`Schemas/Templates`** for MDR (e.g. `mdr::2.1` — always check the live template for the current version) and compare with active JSON schemas.
2. Confirm **DOM linkage** integrity — the signal you operationalise must exist and remain authoritative.
3. Consult tenant **`Configurations/systems`** to know which backends are licensed and routed through CoreTide deployments.

---

## Complete field reference

### Top-level

| Field | Type | Required | Notes |
|---|---|---|---|
| `name` | string | Yes | Verb-noun pattern. Prefix with domain for namespace clarity: `WIN`, `EMAIL`, `CLOUD`, `RBA_RR`. **Filename:** dash-case slug from `name` (e.g. `rba-rr-win-encoded-powershell.yaml`); doc paths use the same `slugify()` rules. |
| `references` | object | Optional | `public` (numbered), `internal` (alpha). Same convention as TVMs. |
| `metadata` | object | Yes | Schema: e.g. `mdr::2.1` — verify against live template. Same structure as TVM/DOM metadata. |
| `description` | string | Yes | Structured prose. See description section below. |
| `detection_model` | UUID | Yes | DOM UUID with `# DOM Name` inline comment. Verify UUID exists. |
| `response` | object | Yes | Incident response metadata. See response section. |
| `configurations` | object | Yes | Per-platform detection payloads. See platform sections. |

### `response` fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `alert_severity` | enum | Yes | `Low` (RBA contribution), `Medium` (same-day triage), `High` (immediate triage). Base severity — platforms can override. |
| `playbook` | URL | Recommended | Link to external playbook/wiki page. |
| `responders` | string | Recommended | Team name (e.g. `CSIRC`, `SOC-T2`). Always populate for `PRODUCTION` rules. |
| `procedure.analysis` | string | Recommended | Numbered analyst steps. Include portal navigation, tool commands, customer contact details. |
| `procedure.searches[]` | array | Recommended | Supporting investigation queries. Each: `purpose`, `system`, `query`. |
| `procedure.containment` | string | Optional | Post-true-positive containment guidance. |

---

## Description — structured three-section format

The best MDRs use a consistent structure that separates technical details from detection criteria and exclusions:

```yaml
description: |
  #### MDR Technical Details
  This rule queries [table] for [behaviour pattern]. It targets
  [specific technique] as documented in [DOM reference].

  #### Detection Criteria
  - Threshold: `failureCountThreshold = 30` (agreed with stakeholders)
  - Time window: 1 hour sliding
  - Entity scope: per-user, per-IP

  #### Exclusion Criteria
  - Service accounts matching `svc_*` pattern excluded via watchlist
  - Known VPN egress IPs excluded via `known_egress_ips` lookup
  - Rationale: [why each exclusion is safe]
```

**Rules**:
- Use YAML `|` block scalar always.
- Separate **what** (technical details), **when** (detection criteria), and **what's excluded** (exclusion criteria).
- Document thresholds with rationale ("agreed with stakeholders", "based on 30-day baseline").
- Reference the DOM signal this MDR implements.

---

## Platform configurations

Each key under `configurations` is a platform identifier. All are optional — an MDR may target one or many platforms.

### Sentinel (`configurations.sentinel`)

| Field | Notes |
|---|---|
| `schema` | e.g. `sentinel::2.4` — verify against live template. |
| `status` | `PRODUCTION`, `DEVELOPMENT`, `DEPRECATED`. Required for deployment automation. |
| `trigger.operator` / `trigger.threshold` | e.g. `GreaterThan` / `0`. Omit for NRT. |
| `scheduling.frequency` / `scheduling.lookback` | Format `Xd\|h\|m`. Lookback >= frequency + ~5min ingestion buffer. Omit for NRT. |
| `scheduling.nrt` | Boolean. For near-real-time rules. |
| `alert.create_incident` | Boolean. |
| `alert.suppression` | Boolean or duration string. |
| `alert.title` / `alert.description` | Support `{{columnName}}` placeholders for dynamic content. |
| `alert.severity` / `alert.tactics` / `alert.techniques` | Override MDR-level values. |
| `alert.custom_details[]` | `key`/`column` pairs (up to 20, max 4KB). |
| `grouping.event` | `AlertPerResult` or `SingleAlert`. |
| `grouping.alert` | Incident grouping: `enabled`, `reopen_closed_incidents`, `grouping_lookback`, `matching`. |
| `entities[]` | Array of `entity` + `mappings[]` (`identifier`/`column`). Map at minimum: Account, IP, Host. |
| `exclusions[]` | Tenant-scoped: `tenant`, `reason`, `let`, `query`. |
| `query` | KQL block scalar. Follow `kusto-query-language` + `microsoft-sentinel` skills. |

### Defender for Endpoint (`configurations.defender_for_endpoint`)

| Field | Notes |
|---|---|
| `schema` | e.g. `defender_for_endpoint::2.1` — verify against live template. |
| `status` | Lifecycle status. |
| `scheduling` | Frequency enum. Engine manages lookback — do NOT add explicit `Timestamp` filters. |
| `alert.title` / `alert.description` | Support `{{columnName}}` placeholders. |
| `alert.category` / `alert.techniques[]` / `alert.severity` | Alert metadata. |
| `alert.recommendation` | Analyst guidance surfaced in the alert. |
| `impacted_entities` | `.device`, `.mailbox`, `.user` — column names from query results. |
| `actions` | `.devices.*` (isolate, collect, scan), `.files.*` (allow/block, quarantine), `.users.*` (mark compromised, disable, force reset). |
| `scope` | `.selection` (`All` or `Specific`), `.device_groups[]`. |
| `exclusions[]` | Same tenant-scoped pattern as Sentinel. |
| `query` | KQL block scalar. Must include `Timestamp`, `DeviceId`, `ReportId` in output. Follow `kusto-query-language` + `microsoft-defender-endpoint` skills. |

### Splunk (`configurations.splunk`)

| Field | Notes |
|---|---|
| `schema` | e.g. `splunk::2.1` — verify against live template. |
| `status` | Lifecycle status. |
| `threshold` | Integer, default 0. |
| `throttling.fields` / `throttling.duration` | Dedup fields + suppression window. Choose fields that define alert uniqueness. |
| `scheduling.cron` / `scheduling.frequency` / `scheduling.lookback` | Scheduling options. |
| `notable.event.title` / `.description` | Use `$token$` syntax for field substitution. |
| `notable.drilldown.name` / `.search` | Secondary investigation search. |
| `notable.security_domain` | e.g. `Threat`, `Identity`, `Network`. |
| `risk.message` | `$field$` token syntax. |
| `risk.risk_objects[]` | `field`, `type` (`user`/`system`), `score` (integer with documented rationale). |
| `risk.threat_objects[]` | `field`, `type` (e.g. `ip`, `command`, `file_hash`). |
| `query` | SPL block scalar. Follow `splunk-spl-processing` skill. |

### Carbon Black Cloud (`configurations.carbon_black_cloud`)

| Field | Notes |
|---|---|
| `schema` | e.g. `carbon_black_cloud::2.0` — verify against live template. |
| `status` | Lifecycle status. |
| `watchlist` / `report` | Override default watchlist/report name. |
| `tags[]` | Custom tags for taxonomy. |
| `severity` | Override integer score. |
| `query` | CBC query string. Follow `carbon-black-cloud` skill. |

---

## Response procedure authoring

The `response.procedure` block is what analysts see when the rule fires. Quality here directly impacts mean-time-to-respond.

### Great procedure pattern

> The `searches` block below uses KQL as an example — adapt the query language to the target platform.

```yaml
procedure:
  analysis: |
    1. Review the alert details and identify the affected user/device.
    2. Navigate to [Portal] > [Section] > [Page] to view the full event context.
    3. Run the supporting search below to identify related activity.
    4. Check the exclusion watchlist — if the entity is listed, close as FP.
    5. If confirmed TP, escalate to [team] and proceed to containment.
  searches:
    - purpose: Identify related authentication activity for the affected user
      system: sentinel
      query: |
        SigninLogs
        | where TimeGenerated > ago(24h)
        | where UserPrincipalName == "{{UserPrincipalName}}"
        | project TimeGenerated, IPAddress, Location, ResultType, AppDisplayName
  containment: |
    1. Disable the affected account via Entra ID.
    2. Revoke all active sessions.
    3. Reset credentials and re-enrol MFA.
    4. Notify the user's manager.
```

### Mediocre procedure pattern

```yaml
procedure:
  analysis: "Investigate the alert."
```

---

## Exclusion discipline

Exclusions are the most dangerous part of an MDR — they create permanent blind spots.

### Rules

1. Every exclusion must have a `reason` explaining why it is safe.
2. Exclusions are **tenant-scoped** — what's safe in one environment may not be in another.
3. Use `let` variables for exclusion lists to make them visible and auditable.
4. Review exclusions quarterly — stale exclusions become attacker-friendly territory.
5. Document expected FP sources in the MDR `description` (Exclusion Criteria section).

```yaml
exclusions:
  - tenant: production-eu
    reason: Vulnerability scanner generates high-volume 4625 events
    let: excluded_scanners
    query: |
      let excluded_scanners = datatable(IPAddress: string) [
          "10.0.1.50", "10.0.1.51"
      ];
```

---

## Skill pairing for query authoring

| Stack | Skill pairing |
|-------|----------------|
| Sentinel & Log Analytics | `kusto-query-language` + `microsoft-sentinel` |
| Defender for Endpoint | `kusto-query-language` + `microsoft-defender-endpoint` |
| Splunk SPL / ES correlation | `splunk-spl-processing` |
| CrowdStrike Falcon | `crowdstrike-falcon` |
| SentinelOne Singularity | `sentinelone-singularity` |
| Carbon Black Cloud | `carbon-black-cloud` |
| HarfangLab | `harfanglab` |

Avoid shipping vendor-specific artefacts your manifest does not advertise — explicitly annotate gaps ("Sentinel backlog item #123") instead of placeholders that read as executable content.

---

## Anti-patterns

| Anti-pattern | Fix |
|---|---|
| **Terse one-line description** | Use the three-section structure: Technical Details, Detection Criteria, Exclusion Criteria |
| **No `procedure` block** | Every `PRODUCTION` rule needs analyst handling guidance |
| **No `playbook` link** | Link to the formal playbook when one exists |
| **Empty/commented-out platform blocks** | Remove platforms you don't target. Don't leave `#sentinel:` noise. |
| **Hardcoded org-specific macros without docs** | Document what macros resolve to, or use inline `let` variables |
| **Risk scores without justification** | Document why `score: 5` vs `score: 10` |
| **Missing entity/risk mappings** | Map at minimum: Account, IP, Host (Sentinel) or user/system risk objects (Splunk) |
| **Schema version drift** | Always check the live template for the current schema version |
| **Inline comment as sole DOM linkage** | Verify the `detection_model` UUID exists in the DOM library |
| **Missing containment on High-severity rules** | High-severity rules must have containment guidance |
| **Inconsistent query output columns** | Standardise output column names across rules for the same platform |

---

## Quality checklist

- [ ] `name` uses verb-noun pattern with domain prefix.
- [ ] `metadata.schema` matches the current live template version.
- [ ] `detection_model` UUID verified against DOM library.
- [ ] `description` uses three-section structure (Technical Details, Detection Criteria, Exclusion Criteria).
- [ ] `response.alert_severity` calibrated: High = immediate, Medium = same-day, Low = RBA only.
- [ ] `response.responders` populated for `PRODUCTION` rules.
- [ ] `response.procedure.analysis` has numbered analyst steps.
- [ ] `response.procedure.searches` has at least one supporting query for Medium+ severity.
- [ ] `response.procedure.containment` populated for High severity rules.
- [ ] Platform `configurations.*.status` set (`PRODUCTION`, `DEVELOPMENT`, `DEPRECATED`).
- [ ] Platform `configurations.*.query` follows the relevant query language + platform skill.
- [ ] Entity mappings (Sentinel) or risk objects (Splunk) populated.
- [ ] Exclusions carry `reason` and are tenant-scoped.
- [ ] No commented-out platform blocks remain.
- [ ] Thresholds documented with rationale.
- [ ] Risk scores documented with rationale.

---

## Collaboration with neighbouring skills

- Upstream **`opentide-detection-objective`** for signal specifications.
- Upstream **`opentide-threat-vector`** for threat context.
- **`detection-engineering`** for hunt-to-rule conversion lifecycle.
- **`mitre-attack`** for technique precision in platform metadata.
- **Platform/query skills** for query authoring discipline.
