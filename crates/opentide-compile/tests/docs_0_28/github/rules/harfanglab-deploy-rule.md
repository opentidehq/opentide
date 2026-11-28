[Catalogue](../README.md) / [Detection rules](README.md)

# HarfangLab Deploy Rule

*Detection rule · `rule::1.0` · version 1 · modified 2026-01-02 · TLP:CLEAR*

Simulated HarfangLab rule for CLI E2E corpus (deploy-only).

| Property | Value |
| --- | --- |
| Severity | High |
| Detection model | [Credential Access Objective](../objectives/credential-access-objective.md) |
| ATT&CK | [`T1059`](https://attack.mitre.org/techniques/T1059) Command and Scripting Interpreter |
| Platforms | HarfangLab: `STAGING` (PREVIEW runs) |

**On this page:** [Deployment](#deployment) · [Platform configuration](#platform-configuration) · [Response](#response) · [ATT&CK techniques](#attck-techniques) · [Detection coverage](#detection-coverage) · [Metadata](#metadata)

## Deployment

What `opentide deploy` does with this rule: each platform block's status, the runs that act on it, and the tenants they reach.

| Platform | Status | Deployed by | Tenants | Block enabled |
| --- | --- | --- | --- | --- |
| HarfangLab | `STAGING` | PREVIEW runs | no tenant configured | yes |

- `STAGING` (strategy `PREVIEW`): Deployed in staging environment for operational testing

> [!WARNING]
> HarfangLab configures no tenant: a run that deploys this block fails until one is added to the platform file.

```mermaid
flowchart LR
    accTitle: Deployment map of HarfangLab Deploy Rule
    accDescr: The platforms the rule deploys to, at their status, and the tenants each run reaches.
    subgraph lane1["Detection rule"]
        rul1["HarfangLab Deploy Rule"]
    end
    subgraph lane2["Platforms"]
        plt1[("HarfangLab<br>STAGING")]
    end
    rul1 --> plt1
    classDef rule fill:#e9f7ef,stroke:#067647,color:#053321
    classDef platform fill:#f2f4f7,stroke:#475467,color:#101828
    classDef focus stroke-width:3px
    class rul1 rule
    class plt1 platform
    class rul1 focus
    style lane1 fill:transparent,stroke:#98a2b3,stroke-dasharray:4 4
    style lane2 fill:transparent,stroke:#98a2b3,stroke-dasharray:4 4
```

*Shapes:* rectangle = detection rule; cylinder = platform; bold outline = this page. *Lines:* solid line = deployed, by the runs named on the line.

## Platform configuration

### HarfangLab

Status `STAGING` · deployed by PREVIEW runs · tenants: no tenant configured

| Setting | Value | Description |
| --- | --- | --- |
| `name` | HarfangLab Deploy Rule | Platform-specific rule name. |
| `maturity` | `Experimental` *(default)* | Rule maturity. |
| `confidence` | `Moderate` *(default)* | Analyst confidence. |
| `action` | `Alert` | What the agent does on a match. |
| `sigma.logsource.category` | `process_creation` | Sigma logsource category (`process_creation`). |
| `sigma.logsource.product` | `windows` | Sigma logsource product (`windows`). |
| `sigma.condition` | `selection` | Sigma condition expression (`selection`, `selection1 and selection2`). |

**`sigma.selections`**: Named selections.

| `name` | `field` | `value` |
| --- | --- | --- |
| `selection` | `Image` | `cmd.exe` |

## Response

| Property | Value |
| --- | --- |
| Alert severity | High |

## ATT&CK techniques

| Technique | Name | Tactics | Summary |
| --- | --- | --- | --- |
| [`T1059`](https://attack.mitre.org/techniques/T1059) | Command and Scripting Interpreter | Execution | Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. |

## Detection coverage

```mermaid
flowchart LR
    accTitle: Detection coverage of HarfangLab Deploy Rule
    accDescr: Threat vectors on the left are detected by the objectives, signals and rules to their right.
    subgraph lane1["Threat vectors"]
        thr1{{"Simulated Actor"}}
    end
    subgraph lane2["Detection objectives"]
        obj1(["Credential Access<br>Objective"])
    end
    subgraph lane3["Detection rules"]
        rul1["HarfangLab Deploy Rule"]
    end
    thr1 --> obj1
    obj1 --> rul1
    classDef threat fill:#fdecea,stroke:#b42318,color:#3d0c09
    classDef objective fill:#fff4e5,stroke:#b54708,color:#3d1d02
    classDef rule fill:#e9f7ef,stroke:#067647,color:#053321
    classDef focus stroke-width:3px
    class thr1 threat
    class obj1 objective
    class rul1 rule
    class rul1 focus
    style lane1 fill:transparent,stroke:#98a2b3,stroke-dasharray:4 4
    style lane2 fill:transparent,stroke:#98a2b3,stroke-dasharray:4 4
    style lane3 fill:transparent,stroke:#98a2b3,stroke-dasharray:4 4
```

*Shapes:* hexagon = threat vector; stadium = detection objective; rectangle = detection rule; bold outline = this page.

### Related objects

| Type | Object | Direction |
| --- | --- | --- |
| Threat | [Simulated Actor](../threats/simulated-actor.md) | Upstream |
| Objective | [Credential Access Objective](../objectives/credential-access-objective.md) | Upstream |

## Metadata

| Field | Value |
| --- | --- |
| UUID | `00000000-0000-4000-8003-000000000007` |
| Schema | `rule::1.0` |
| Version | `1` |
| Created | `2026-01-01` |
| Modified | `2026-01-02` |
| TLP | clear (`TLP:CLEAR`) |

<!-- Generated by opentide (opentide generate docs). Edit the object's YAML instead: this page is rewritten on every run. -->
