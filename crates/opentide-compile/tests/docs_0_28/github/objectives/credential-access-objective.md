[Catalogue](../README.md) / [Detection objectives](README.md)

# Credential Access Objective

*Detection objective · `objective::1.0` · version 1 · modified 2026-01-02 · TLP:CLEAR*

Detect credential access techniques

| Property | Value |
| --- | --- |
| Priority | High |
| Type | Threat |
| Composition | Combined |
| Threats addressed | [Simulated Actor](../threats/simulated-actor.md) |
| Signals | 1 signal |
| Detection rules | 10 rules |
| Platforms | Carbon Black Cloud, CrowdStrike Falcon, Elastic Security, HarfangLab, Microsoft Defender for Endpoint, Microsoft Sentinel, SentinelOne, Splunk Enterprise Security, Sysdig Secure |

> [!WARNING]
> 1 of 1 signal has no implementing rule yet: *Suspicious logon signal*.

**On this page:** [Composition](#composition) · [Threats addressed](#threats-addressed) · [Signals](#signals) · [Detection coverage](#detection-coverage) · [Metadata](#metadata)

## Composition

**Combined**: All signals triggered for any entity can be grouped in a single signal. This may be extremely useful to identify pan-environment compromises.

Compose signals for credential access detection

## Threats addressed

| Threat vector | Criticality | Kill chain |
| --- | --- | --- |
| [Simulated Actor](../threats/simulated-actor.md) | High | - |

## Signals

| Signal | Severity | Methodology | Effort | Rules | Platforms and status |
| --- | --- | --- | --- | --- | --- |
| [Suspicious logon signal](#suspicious-logon-signal) | Medium | Statistical | - | *None yet* | - |
| *Objective as a whole* | - | - | - | [Carbon Black Lucene Rule](../rules/carbon-black-lucene-rule.md)<br>[CrowdStrike Deploy Rule](../rules/crowdstrike-deploy-rule.md)<br>[Defender KQL Rule](../rules/defender-kql-rule.md)<br>[Elastic KQL Rule](../rules/elastic-kql-rule.md)<br>[HarfangLab Deploy Rule](../rules/harfanglab-deploy-rule.md)<br>[Sentinel KQL Rule](../rules/sentinel-kql-rule.md)<br>[SentinelOne S1QL Rule](../rules/sentinelone-s1ql-rule.md)<br>[Splunk SPL Rule](../rules/splunk-spl-rule.md)<br>[Staging Promote Rule](../rules/staging-promote-rule.md)<br>[Sysdig Falco Rule](../rules/sysdig-falco-rule.md) | Carbon Black Cloud `STAGING`<br>CrowdStrike Falcon `STAGING`<br>Microsoft Defender for Endpoint `STAGING`<br>Elastic Security `STAGING`<br>HarfangLab `STAGING`<br>Microsoft Sentinel `STAGING`<br>SentinelOne `STAGING`<br>Splunk Enterprise Security `STAGING`<br>Microsoft Sentinel `STAGING`<br>Sysdig Secure `STAGING` |

### Suspicious logon signal

Suspicious authentication activity

- **Data:** Complete. Security event logs
- **Entities:** Hostname
- **Implemented by:** *no rule yet*
- **UUID:** `00000000-0000-4000-8099-000000000001`

## Detection coverage

```mermaid
flowchart LR
    accTitle: Detection coverage of Credential Access Objective
    accDescr: Threat vectors on the left are detected by the objectives, signals and rules to their right.
    subgraph lane1["Threat vectors"]
        thr1{{"Simulated Actor"}}
    end
    subgraph lane2["Detection objectives"]
        obj1(["Credential Access<br>Objective"])
    end
    subgraph lane3["Signals"]
        sig1(("Suspicious logon signal"))
    end
    subgraph lane4["Detection rules"]
        rul1["Carbon Black Lucene Rule"]
        rul2["CrowdStrike Deploy Rule"]
        rul3["Defender KQL Rule"]
        rul4["Elastic KQL Rule"]
        rul5["HarfangLab Deploy Rule"]
        rul6["Sentinel KQL Rule"]
        rul7["SentinelOne S1QL Rule"]
        rul8["Splunk SPL Rule"]
        rul9["Staging Promote Rule"]
        rul10["Sysdig Falco Rule"]
    end
    thr1 --> obj1
    obj1 --> sig1
    obj1 --> rul1
    obj1 --> rul2
    obj1 --> rul3
    obj1 --> rul4
    obj1 --> rul5
    obj1 --> rul6
    obj1 --> rul7
    obj1 --> rul8
    obj1 --> rul9
    obj1 --> rul10
    classDef threat fill:#fdecea,stroke:#b42318,color:#3d0c09
    classDef objective fill:#fff4e5,stroke:#b54708,color:#3d1d02
    classDef signal fill:#eaf2fd,stroke:#1d4ed8,color:#0b1f4d
    classDef rule fill:#e9f7ef,stroke:#067647,color:#053321
    classDef focus stroke-width:3px
    class thr1 threat
    class obj1 objective
    class sig1 signal
    class rul1,rul2,rul3,rul4,rul5,rul6,rul7,rul8,rul9,rul10 rule
    class obj1 focus
    style lane1 fill:transparent,stroke:#98a2b3,stroke-dasharray:4 4
    style lane2 fill:transparent,stroke:#98a2b3,stroke-dasharray:4 4
    style lane3 fill:transparent,stroke:#98a2b3,stroke-dasharray:4 4
    style lane4 fill:transparent,stroke:#98a2b3,stroke-dasharray:4 4
```

*Shapes:* hexagon = threat vector; stadium = detection objective; circle = detection signal; rectangle = detection rule; bold outline = this page.

### Related objects

| Type | Object | Direction |
| --- | --- | --- |
| Threat | [Simulated Actor](../threats/simulated-actor.md) | Upstream |
| Signal | [Suspicious logon signal](credential-access-objective.md#suspicious-logon-signal) | Downstream |
| Rule | [Carbon Black Lucene Rule](../rules/carbon-black-lucene-rule.md) | Downstream |
| Rule | [CrowdStrike Deploy Rule](../rules/crowdstrike-deploy-rule.md) | Downstream |
| Rule | [Defender KQL Rule](../rules/defender-kql-rule.md) | Downstream |
| Rule | [Elastic KQL Rule](../rules/elastic-kql-rule.md) | Downstream |
| Rule | [HarfangLab Deploy Rule](../rules/harfanglab-deploy-rule.md) | Downstream |
| Rule | [Sentinel KQL Rule](../rules/sentinel-kql-rule.md) | Downstream |
| Rule | [SentinelOne S1QL Rule](../rules/sentinelone-s1ql-rule.md) | Downstream |
| Rule | [Splunk SPL Rule](../rules/splunk-spl-rule.md) | Downstream |
| Rule | [Staging Promote Rule](../rules/staging-promote-rule.md) | Downstream |
| Rule | [Sysdig Falco Rule](../rules/sysdig-falco-rule.md) | Downstream |

## Metadata

| Field | Value |
| --- | --- |
| UUID | `00000000-0000-4000-8002-000000000001` |
| Schema | `objective::1.0` |
| Version | `1` |
| Created | `2026-01-01` |
| Modified | `2026-01-02` |
| TLP | clear (`TLP:CLEAR`) |

<!-- Generated by opentide (opentide generate docs). Edit the object's YAML instead: this page is rewritten on every run. -->
