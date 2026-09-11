---
name: detection-engineering
description: Detection engineering lifecycle across the OpenTide TVM → DOM → MDR sequence and the operational practice of converting validated hunting queries into production detection rules. Encodes hunting-vs-detection trade-offs, hunt-to-rule conversion (7-step process with FP reduction, entity mapping, NRT compliance, response actions), platform pairing matrix (Microsoft KQL split, Splunk SPL, vendor consoles), maturity progression, PR scope discipline, and quality bars. Use when planning multi-phase detection work, sequencing object types in OpenTide content repos, reviewing PR scope, or operationalising hunts into MDR objects.
---

# Detection engineering — OpenTide + DetectionOps

This skill governs **how** detection content moves through its lifecycle. It pairs OpenTide's object lineage (Threat Vector → Detection Objective → Detection Rule) with the practical mechanics of converting validated hunting queries into production-grade detection rules on the platforms CoreTide deploys to.

> Always pair with: language skills (`kusto-query-language`, `splunk-spl-processing`), platform skills (`microsoft-sentinel`, `microsoft-defender-endpoint`, `crowdstrike-falcon`, `carbon-black-cloud`, `sentinelone-singularity`, `harfanglab`), and the OpenTide object skills (`opentide-threat-vector`, `opentide-detection-objective`, `opentide-detection-rule`).

---

## 1. OpenTide sequencing

1. **Evidence / threat modelling** — `opentide-threat-vector` (TVM YAML, Phase A intel structuring + Phase B authoring).
2. **Detection intent & signals** — `opentide-detection-objective` (DOM YAML, signals, data contracts, methodology).
3. **Deployable artefacts** — `opentide-detection-rule` (MDR YAML, plus platform-specific `configurations.*` blocks).

**Default rule**: one object type per change request unless explicitly running an end-to-end vertical slice (drill, pilot deployment, framework-bootstrap).

CoreTide-aligned configuration keys most commonly seen:

| Key | Platform | Pair with |
|---|---|---|
| `sentinel` | Microsoft Sentinel | `microsoft-sentinel` + `kusto-query-language` |
| `defender_for_endpoint` | M365 Defender Advanced Hunting | `microsoft-defender-endpoint` + `kusto-query-language` |
| `splunk` | Splunk Enterprise / ES | `splunk-spl-processing` |
| `crowdstrike` | CrowdStrike Falcon | `crowdstrike-falcon` |
| `carbon_black_cloud` | VMware Carbon Black Cloud | `carbon-black-cloud` |
| `sentinel_one` | SentinelOne Singularity | `sentinelone-singularity` |
| `harfanglab` | HarfangLab orb | `harfanglab` |

Always confirm the exact keys against the active meta-schema and the `Configurations/systems` directory of the content repository — keys evolve.

---

## 2. Hunting versus production detection

| Aspect | Hunting query | Production detection rule |
|---|---|---|
| Purpose | Retroactive investigation; evidence search | Continuous monitoring; alert future activity |
| Execution | One-shot, ad-hoc | Automated, recurring, NRT or scheduled |
| Result handling | Analyst reviews full result set | Each row → alert (+ optional response action) |
| Time filter | Explicit lookback (e.g., last N days) | Platform-managed (frequency + lookback) |
| Output columns | Flexible — whatever helps triage | **Mandatory** schema for alert generation |
| FP tolerance | Some FPs acceptable | Low — every FP degrades analyst trust |
| Tuning lifecycle | Per-hunt threshold tweaks | Stabilised before deployment; monitored continuously |
| Scope | Full fleet or targeted | Often scoped to device/entity groups |

### Design philosophy

1. **Start from validated hunts.** Never deploy a detection without hunting validation.
2. **Minimise FPs.** Every FP is a noise alert that erodes analyst trust.
3. **Start conservative.** Lower severity, "investigate" response actions, escalate after stability is established.
4. **Document everything.** Detections must carry the same rationale quality as hunting queries.
5. **Test inside the frequency window.** Run the candidate query with the production lookback to confirm result counts are manageable.

### Maturity progression

```
THEORETICAL → VALIDATED hunt → Detection candidate → Deployed (conservative) → Tuned (production)
```

A hunt may become a detection only after:
- Hunting status is `VALIDATED`.
- True positives are confirmed.
- FP rate is documented.
- Filters are tuned to reduce noise.
- Expected result volume is known for the target frequency.

---

## 3. Pairing languages and platforms

| Technology family | Query expression | Skills |
|---|---|---|
| Microsoft Sentinel + Defender Advanced Hunting | KQL | Shared: `kusto-query-language`; platform-specific: `microsoft-sentinel`, `microsoft-defender-endpoint` |
| Splunk Enterprise / ES | SPL | `splunk-spl-processing` |
| CrowdStrike Falcon | FQL / NG-SIEM (LogScale) | `crowdstrike-falcon` |
| SentinelOne Singularity | Star Custom Logic / Deep Visibility / PowerQuery | `sentinelone-singularity` |
| Carbon Black Cloud Enterprise EDR | Watchlist / process search syntax | `carbon-black-cloud` |
| HarfangLab orb | Sigma + RHQL | `harfanglab` |

**Never invent vendor syntax.** If the relevant platform skill does not assert a fact, route to vendor documentation rather than fabricating syntax.

---

## 4. Hunt-to-detection conversion — 7 steps

### Pre-conversion checklist

- [ ] Hunt query has `validation_status: VALIDATED`.
- [ ] True positives confirmed in production telemetry.
- [ ] FP rate documented from hunt iterations.
- [ ] Filters tuned based on hunt observations.
- [ ] Expected result volume known for the target frequency window.

### Step 1 — Adjust the time filter

Remove or replace the hunting time window with the platform's scheduling mechanism.

| Platform pattern | Action |
|---|---|
| **Scheduled rule** (any SIEM/EDR) | Replace the ad-hoc lookback with the platform's frequency + ingestion buffer |
| **Near-real-time / streaming rule** | Remove explicit time filters — the engine manages ingestion-time windowing |
| **Continuous query / saved search** | Align the `earliest`/`latest` (SPL) or equivalent to the scheduled interval |

> Platform-specific time-filter mechanics (field names, NRT semantics, ingestion-time functions) live in the relevant platform skill. Consult `microsoft-sentinel`, `microsoft-defender-endpoint`, `splunk-spl-processing`, `crowdstrike-falcon`, etc.

### Step 2 — Add required output columns

Every platform mandates certain columns for alert generation and entity mapping. The general contract:

| Column category | Purpose | Examples |
|---|---|---|
| **Timestamp** | When the event occurred | Platform-specific timestamp field |
| **Entity identifiers** | Map alerts to devices, users, IPs, files | Account name, hostname, IP address, file hash |
| **Mandatory platform fields** | Required by the alert engine | Platform-specific — rule creation fails without them |
| **Enrichment** | Context for triage | Application name, risk level, geo-location |

> Consult the platform skill for the exact required-column schema. Some platforms (e.g., Defender custom detections) enforce strict mandatory columns; others (e.g., Splunk correlation searches) use notable-event field mappings.

### Step 3 — Reduce false positives

For each FP class observed during hunting, add a targeted exclusion **with a justification comment**:

**Principles** (platform-agnostic):
- One exclusion per FP scenario — no blanket suppressions.
- Each exclusion carries a comment explaining the FP class.
- Group environment-specific exclusions in a clearly marked block so deployers can customise per site.
- Reviewers reject undocumented exclusions.

**Pattern** (pseudocode):

```
// Exclude known-good tool in expected path (FP: scheduled backup agent)
FILTER OUT (filename = "legitimate_tool" AND path CONTAINS "KnownGoodPath")

// Exclude service accounts (FP: monitoring infrastructure)
FILTER OUT (account IN ["svc_monitoring", "svc_backup"])

// --- BEGIN ENVIRONMENT FILTERS (customise per deployment) ---
// <site-specific exclusions here>
// --- END ENVIRONMENT FILTERS ---
```

> For platform-specific filter syntax (`where not(...)` in KQL, `NOT` in SPL, exclusion predicates in FQL/DVQL), see the relevant language/platform skill.

### Step 4 — Test with the frequency lookback

Run the candidate query for the production lookback window. Verify:
- Result count within the platform's alert-per-run limit (commonly ≤ 150).
- Results actionable (not dominated by FPs).
- No critical events fall outside the lookback window.

### Step 5 — Map entities

Every platform links alert fields to entity types for incident correlation. The universal entity categories are:

| Entity type | Typical identifier fields | Purpose |
|---|---|---|
| **Device / Host** | Hostname, device ID, MAC address | Scope affected endpoints |
| **Account / User** | Username, UPN, SID, directory object ID | Identify compromised identities |
| **IP address** | Source IP, destination IP | Network correlation |
| **File** | File name, hash (SHA-256), path | Artefact tracking |
| **Process** | Process ID, command line, parent process | Execution chain analysis |
| **URL / Domain** | URL, FQDN | Web/C2 indicators |
| **Mailbox** | Email address | Email-based attacks |
| **Cloud resource** | Resource ID, subscription, project | Cloud-plane correlation |

> Each platform has its own column-name conventions and mapping mechanisms (Sentinel entity mapping UI, Defender mandatory projection columns, Splunk ES `drilldown_*` fields, Falcon detection metadata, S1 Storyline fields). Consult the relevant platform skill for exact field names.

### Step 6 — Set conservative response actions

| Maturity stage | Recommended response | Rationale |
|---|---|---|
| **Initial deployment** | Alert-only / case creation / "investigate" | Build confidence before automation |
| **Stabilised (low FP rate confirmed)** | Automated enrichment (lookups, context gathering) | Reduce analyst toil without risk |
| **Production (proven reliable)** | Automated containment (isolate, disable, quarantine) | High-confidence rules only |

**Principles**:
- Default to the least disruptive response action.
- Reserve automated containment for high-confidence, critical-severity rules with a proven track record.
- Add response automation (playbooks, workflows, RTR scripts) only after the detection has demonstrated stability.
- Document the escalation criteria for moving to more aggressive response actions.

### Step 7 — Handle near-real-time (NRT) constraints

NRT / streaming rules trade latency for constraints. Common restrictions across platforms:

| Constraint area | Typical NRT limitation |
|---|---|
| **Table scope** | Some platforms restrict NRT to a single data source per rule |
| **Query complexity** | Wildcards, cross-resource queries, external data lookups often prohibited |
| **Comments / formatting** | Some engines strip or reject inline comments |
| **Time filters** | Must be removed — the NRT engine manages the ingestion window |
| **Rule quotas** | Platforms may cap the number of concurrent NRT rules |
| **Query length** | Character limits may be stricter than scheduled rules |

**NRT pre-flight** (platform-agnostic):
1. Confirm the target data source supports NRT on the chosen platform.
2. Verify the query meets NRT complexity restrictions.
3. Check the workspace/tenant NRT rule quota.
4. Remove explicit time filters.
5. Test that the query returns results within the NRT latency window.

> For platform-specific NRT constraints (Defender NRT single-table + no-comments rule, Sentinel 50-rule cap, Splunk real-time search resource implications), see the relevant platform skill.

### Conversion checklist

- [ ] Time filter removed/adjusted per target platform.
- [ ] Required output columns present (platform-specific mandatory + entity identifiers).
- [ ] FPs from hunting excluded with justification comments.
- [ ] Result volume tested under frequency lookback (within platform alert-per-run cap).
- [ ] Entity columns in projection for alert correlation.
- [ ] Response actions conservative (alert-only for initial deployment).
- [ ] NRT constraints satisfied where applicable (table scope, query complexity, quotas).
- [ ] Severity set conservatively with documented escalation criteria.
- [ ] Alert enrichment (custom details, dynamic title tokens) configured.
- [ ] MITRE technique + tactic mapped.
- [ ] Multi-platform parity checked if the MDR targets more than one `configurations.*` key.

---

## 5. Detection rule quality standards

### Query quality (in addition to language-skill bar)

- [ ] No unnecessary complexity — detection queries should be **simpler** than hunting queries.
- [ ] Deterministic — no random sampling, no probabilistic filters.
- [ ] Stable output schema — column names consistent run-to-run for entity mapping.
- [ ] Designed to produce results within the platform's per-run alert limit (check platform skill for exact cap).

### Documentation quality

Every rule must document, in MDR YAML or platform metadata:

| Field | Content |
|---|---|
| Detection name | Clear, descriptive |
| Frequency | Chosen frequency with justification |
| Severity | Chosen severity with escalation criteria |
| MITRE | Technique IDs + tactics |
| Entity mapping | Which columns map to which entities |
| Response actions | Configured actions and rationale |
| FP exclusions | Each exclusion with justification |
| Tuning guidance | How to adjust thresholds/exclusions per deployment |
| Source hunt | Reference to the validated hunting query/lead |

### Tuning philosophy

1. **Start broad, narrow carefully** — begin with the hunt's filters and add exclusions one at a time.
2. **Document every exclusion** — `where not(...)` without a comment is rejected.
3. **`let` for thresholds** — make tuning parameters explicit and adjustable.
4. **Monitor alert volume** — track alerts/week and investigate sudden changes.
5. **Review quarterly** — re-evaluate relevance against the current threat landscape.

---

## 6. Cross-platform detection capabilities

Different platforms expose different rule types, response mechanisms, and constraints. This matrix summarises the **capability categories** — consult each platform skill for exact syntax and field names.

| Capability | SIEM (scheduled) | SIEM (NRT / streaming) | EDR custom detection | EDR real-time rule | Vendor console rule |
|---|---|---|---|---|---|
| **Scheduling** | Cron / interval | Continuous ingestion window | Frequency-based | Event-driven | Platform-managed |
| **Multi-source joins** | Usually supported | Often restricted | Typically single-table | Single event stream | Varies |
| **Entity mapping** | Platform-specific UI/fields | Same as scheduled | Mandatory projection columns | Automatic from event | Vendor-defined |
| **Response actions** | Playbook / SOAR integration | Same as scheduled | Device isolate, file quarantine, user disable | Alert + optional block | Alert / case / block |
| **Alert grouping** | Entity-based or event-based | Event-based | Dedup by report/event ID | Per-event | Vendor-defined |
| **MITRE mapping** | Rule metadata / UI | Same as scheduled | Rule metadata | Rule metadata | Varies |
| **NRT constraints** | n/a | Table limits, query restrictions, rule quotas | n/a | Complexity limits | Vendor-specific |
| **Alert volume cap** | Platform-specific per-run limit | Throughput-based | Platform-specific per-run limit | Rate-limited | Varies |

### Platform skill routing

| Platform family | Detection rule type | Skill |
|---|---|---|
| Microsoft Sentinel | Scheduled analytic rule, NRT rule | `microsoft-sentinel` |
| Microsoft Defender | Custom detection rule, NRT | `microsoft-defender-endpoint` |
| Splunk Enterprise / ES | Correlation search, scheduled search, real-time search | `splunk-spl-processing` |
| CrowdStrike Falcon | Custom IOA, NG-SIEM rule, Fusion workflow | `crowdstrike-falcon` |
| SentinelOne Singularity | STAR Custom Logic rule | `sentinelone-singularity` |
| Carbon Black Cloud | Watchlist report, scheduled query | `carbon-black-cloud` |
| HarfangLab | Sigma rule pack, custom detection rule | `harfanglab` |

---

## 7. Multi-platform deployment discipline

When an MDR object targets multiple `configurations.*` keys (e.g., both `sentinel` and `splunk`), each platform binding must be independently valid.

### Parity checklist

- [ ] Each platform configuration compiles/validates in its native environment.
- [ ] Detection logic is semantically equivalent across platforms (same behaviour detected, same entity scope).
- [ ] Platform-specific FP exclusions are documented separately — filter syntax differs, and environment-specific exclusions may vary.
- [ ] Entity mapping uses each platform's native field conventions.
- [ ] Alert severity and response actions are calibrated per platform (a "Medium" in one SIEM may not map to "Medium" in another).
- [ ] NRT / real-time variants are only created where the platform supports them for the target data source.

### Acceptable divergence

Not all platforms have equivalent capabilities. Document divergence explicitly:

| Divergence type | Example | Action |
|---|---|---|
| **Missing data source** | EDR telemetry not available in SIEM | Skip platform; note in MDR `data_requirements` |
| **No NRT support** | Platform lacks streaming rules for the target table | Deploy scheduled-only; document latency trade-off |
| **Different join semantics** | SIEM supports cross-table joins; EDR does not | Simplify EDR variant; document coverage delta |
| **Response action gap** | One platform lacks automated containment | Deploy alert-only; document manual escalation path |

---

## 8. Detection metrics and operational health

Track detection effectiveness post-deployment. These metrics feed back into tuning (§5) and maturity progression (§2).

| Metric | Definition | Healthy range | Action if out of range |
|---|---|---|---|
| **True positive rate** | TP / (TP + FP) over trailing period | > 80 % | Tune filters; review FP exclusions |
| **Alert volume** | Alerts per day/week | Stable ± 20 % | Investigate spikes; check for environmental changes |
| **Mean time to triage** | Time from alert to analyst first-touch | < SLA target | Improve enrichment; add context to alert |
| **Detection latency** | Time from event occurrence to alert firing | Within frequency window | Consider NRT; check ingestion delays |
| **Coverage drift** | MITRE techniques covered vs. threat model | Monotonically increasing | Prioritise new detections for uncovered techniques |
| **Rule health** | Rules failing, disabled, or erroring | 0 unhealthy rules | Fix or retire broken rules promptly |

### Quarterly review cycle

1. **Pull metrics** for all active detections.
2. **Identify underperformers** — high FP rate, zero alerts (possible blind spot), or disabled rules.
3. **Re-evaluate relevance** against the current threat landscape and organisational changes.
4. **Retire or refactor** detections that no longer serve the threat model.
5. **Update MDR YAML** and platform configurations to reflect tuning changes.

---

## 9. Detection testing and validation

### Pre-deployment testing

Before promoting a detection from candidate to deployed:

| Test type | Method | Pass criteria |
|---|---|---|
| **Syntax validation** | Platform query validator / dry-run | No errors |
| **Historical replay** | Run against historical data for the lookback window | Results match expected volume; no unexpected FPs |
| **Simulated true positive** | Atomic Red Team, Caldera, manual simulation, or replayed telemetry | Detection fires on simulated attack |
| **FP stress test** | Run during peak business hours / known noisy periods | FP rate within acceptable threshold |

### Regression testing

When modifying an existing detection:

1. **Capture baseline** — record current alert volume, TP/FP ratio, and entity coverage.
2. **Apply change** in a staging environment or with a parallel rule.
3. **Compare** — new results should not lose true positives or introduce new FP classes.
4. **Document** — note what changed and why in the MDR YAML changelog or commit message.

### Attack simulation alignment

Map detections to attack simulation frameworks for continuous validation:

| Framework | Use case | Integration pattern |
|---|---|---|
| MITRE ATT&CK Evaluations | Vendor-neutral technique coverage | Map MDR MITRE fields to evaluation results |
| Atomic Red Team | Per-technique unit tests | One atomic test per detection; automate in CI |
| SCYTHE / Caldera / similar | Multi-step campaign simulation | Validate behavioural-sequence detections end-to-end |
| Purple team exercises | Realistic adversary emulation | Validate detection + response chain holistically |

---

## 10. PR scope discipline (OpenTide change requests)

- Default pull requests contain **one object type at a time** (TVM, DOM, or MDR).
- An end-to-end vertical slice is acceptable when explicitly orchestrated (drill, pilot, framework bootstrap) — call it out in the pull request narrative.
- Detection rule changes that span multiple platform `configurations.*` blocks may live in one MDR file but should be reviewed per-platform.
- Schema/template changes never travel inside a content merge — they go through dedicated framework merges.

---

## 11. References

- `kusto-query-language/SKILL.md` (+ `references/Best-Practices.md`, `references/Hypothesis-Anti-Patterns.md`)
- `microsoft-sentinel/SKILL.md` (+ `references/Anti-Patterns.md`)
- `microsoft-defender-endpoint/SKILL.md` (+ `references/Anti-Patterns.md`)
- `splunk-spl-processing/SKILL.md`
- `crowdstrike-falcon/SKILL.md`, `carbon-black-cloud/SKILL.md`, `sentinelone-singularity/SKILL.md`, `harfanglab/SKILL.md`
- `opentide-threat-vector/SKILL.md`, `opentide-detection-objective/SKILL.md`, `opentide-detection-rule/SKILL.md`
- `threat-hunting/SKILL.md` — hypothesis discipline (ABLE) and hunt quality scoring
