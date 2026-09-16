# Microsoft Defender XDR / MDE tables

Advanced hunting and custom detections query a **fixed schema** of tables. Column-level docs are one Learn page per table.

Primary citations:

- [Data tables in the advanced hunting schema](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables)
- [Advanced hunting query language](https://learn.microsoft.com/defender-xdr/advanced-hunting-query-language)
- [Create custom detection rules](https://learn.microsoft.com/defender-xdr/custom-detection-rules)
- [Stream Defender XDR to Sentinel](https://learn.microsoft.com/azure/sentinel/connect-microsoft-365-defender)

Event time column: **`Timestamp`** (not `TimeGenerated`). When the same table is streamed to Sentinel, **`TimeGenerated`** is also present.

---

## Required / recommended output columns (custom detections)

Citation: [Create custom detection rules — Required columns](https://learn.microsoft.com/defender-xdr/custom-detection-rules)

To create a custom detection on Defender data, Microsoft recommends the query returns:

1. **`Timestamp` or `TimeGenerated`** — alert first/last event time. If omitted, the service uses the detection lookback window.
2. **MDE tables:** **`DeviceId`** and **`ReportId`** — device-group scoping and process-tree construction.
3. **Other Defender tables:** **`Timestamp` and `ReportId` from the same event** — entity scope and alert timeline.
4. **Impacted asset** (for automatic mapping), at least one of:

| Asset | Identifier columns |
| --- | --- |
| Device | `DeviceId`, `DeviceName`, `RemoteDeviceName` |
| Mailbox | `RecipientEmailAddress`, `SenderFromAddress`, `SenderMailFromAddress`, `SenderObjectId`, `RecipientObjectId` |
| Account | `AccountObjectId`, `AccountSid`, `AccountUpn`, `InitiatingProcessAccountSid`, `InitiatingProcessAccountUpn` |

Do **not** filter custom detections on `Timestamp`/`TimeGenerated` except to narrow inside the lookback; the service already time-scopes. Prefer `ingestion_time() > ago(1d)` when you need an extra ingestion-delay-aware bound (example in the same article).

Keep latest event columns when aggregating:

```kusto
| summarize (Timestamp, ReportId) = arg_max(Timestamp, ReportId), count() by DeviceId
```

### Action-specific extra columns

| Action | Required result columns | Citation |
| --- | --- | --- |
| Device isolate / scan / restrict | `DeviceId` | [custom detection rules](https://learn.microsoft.com/defender-xdr/custom-detection-rules) |
| Quarantine file | `SHA1` / `InitiatingProcessSHA1` / `SHA256` / `InitiatingProcessSHA256` | same |
| Mark user compromised | `AccountObjectId` / `InitiatingProcessAccountObjectId` / `RecipientObjectId` | same |
| Disable / reset user (AD) | SID columns: `AccountSid`, `InitiatingProcessAccountSid`, `RequestAccountSid`, `OnPremSid`; Entra: `AccountObjectId` | same |
| SaaS governance (preview) | `AccountObjectId`, `InstanceId`, `ApplicationId`, `AppInstanceId`, `Timestamp` | same |
| Email move/delete | `NetworkMessageId` **and** `RecipientEmailAddress` | same |

Microsoft Sentinel scoping: project `SentinelScope_CF` when workspace scoping is configured.

### Continuous (NRT) extra constraints

- One table only; no `join` / `union` / `externaldata`; no comments.
- NRT-supported Defender tables are listed per table below (`NRT` column).

---

## Endpoint (Microsoft Defender for Endpoint)

| Table | Description | NRT | Citation |
| --- | --- | --- | --- |
| `DeviceProcessEvents` | Process creation | Yes | [DeviceProcessEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| `DeviceNetworkEvents` | Network connections | Yes | [DeviceNetworkEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicenetworkevents-table) |
| `DeviceFileEvents` | File create/modify/delete | Yes | [DeviceFileEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicefileevents-table) |
| `DeviceRegistryEvents` | Registry value/key changes | Yes | [DeviceRegistryEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceregistryevents-table) |
| `DeviceLogonEvents` | Interactive/network logons | Yes | [DeviceLogonEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicelgonevents-table) |
| `DeviceImageLoadEvents` | DLL/image loads | Yes | [DeviceImageLoadEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceimageloadevents-table) |
| `DeviceEvents` | Misc. security-control events (AV, exploit guard, …) | Yes | [DeviceEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceevents-table) |
| `DeviceInfo` | Device inventory / OS | Yes | [DeviceInfo](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceinfo-table) |
| `DeviceNetworkInfo` | Adapters, IP, MAC, domains | Yes | [DeviceNetworkInfo](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicenetworkinfo-table) |
| `DeviceFileCertificateInfo` | Signer certs for files | Yes | [DeviceFileCertificateInfo](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicefilecertificateinfo-table) |

`ActionType` values are documented in the in-portal schema reference, not always fully on Learn. [Schema tables](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables)

---

## Alerts

| Table | Description | NRT | Citation |
| --- | --- | --- | --- |
| `AlertInfo` | Alert metadata (severity, category, title) | No (not on NRT list) | [AlertInfo](https://learn.microsoft.com/defender-xdr/advanced-hunting-alertinfo-table) |
| `AlertEvidence` | Entities attached to alerts | Yes | [AlertEvidence](https://learn.microsoft.com/defender-xdr/advanced-hunting-alertevidence-table) |

---

## Email / Microsoft Defender for Office 365

| Table | Description | NRT | Citation |
| --- | --- | --- | --- |
| `EmailEvents` | Delivery, block, junk | Yes (except `LatestDeliveryLocation`, `LatestDeliveryAction`) | [EmailEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-emailevents-table) |
| `EmailAttachmentInfo` | Attachments | Yes | [EmailAttachmentInfo](https://learn.microsoft.com/defender-xdr/advanced-hunting-emailattachmentinfo-table) |
| `EmailUrlInfo` | URLs in mail | Yes | [EmailUrlInfo](https://learn.microsoft.com/defender-xdr/advanced-hunting-emailurlinfo-table) |
| `EmailPostDeliveryEvents` | ZAP / post-delivery | Yes | [EmailPostDeliveryEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-emailpostdeliveryevents-table) |
| `UrlClickEvents` | Safe Links clicks | Yes | [UrlClickEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-urlclickevents-table) |
| `CampaignInfo` | Email campaigns (preview) | No | [Schema list](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables) |
| `FileMaliciousContentInfo` | MDO-processed files in SPO/OD/Teams (preview) | No | same |

---

## Identity (Defender for Identity / hybrid)

| Table | Description | NRT | Citation |
| --- | --- | --- | --- |
| `IdentityLogonEvents` | AD and Microsoft online auth | Yes | [IdentityLogonEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-identitylogonevents-table) |
| `IdentityQueryEvents` | LDAP/AD object queries | Yes | [IdentityQueryEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-identityqueryevents-table) |
| `IdentityDirectoryEvents` | DC identity & system events | Yes | [IdentityDirectoryEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-identitydirectoryevents-table) |
| `IdentityInfo` | Account snapshot (Entra + others) | No | [IdentityInfo](https://learn.microsoft.com/defender-xdr/advanced-hunting-identityinfo-table) |
| `IdentityAccountInfo` | Account ↔ identity links | No | [Schema list](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables) |
| `IdentityEvents` | Other cloud IdP events (preview) | No | same |

---

## Cloud apps, Entra (XDR copies), Graph

| Table | Description | NRT | Citation |
| --- | --- | --- | --- |
| `CloudAppEvents` | MDA / SaaS / O365 object events | Yes | [CloudAppEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-cloudappevents-table) |
| `AADSignInEventsBeta` | Entra interactive + non-interactive (XDR) | No | [AADSignInEventsBeta](https://learn.microsoft.com/defender-xdr/advanced-hunting-aadsignineventsbeta-table) |
| `AADSpnSignInEventsBeta` | SP and MI sign-ins (XDR) | No | [AADSpnSignInEventsBeta](https://learn.microsoft.com/defender-xdr/advanced-hunting-aadspnsignineventsbeta-table) |
| `EntraIdSignInEvents` | Newer Entra sign-in table | No | [Schema list](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables) |
| `EntraIdSpnSignInEvents` | Newer SP/MI table | No | same |
| `GraphAPIAuditEvents` | Graph API audit | No | same |
| `OAuthAppInfo` | App governance OAuth apps (preview) | No | same |

Prefer Sentinel `SigninLogs` when writing **Sentinel** analytics; use `AADSignInEventsBeta` / `EntraIdSignInEvents` in **Defender** hunting when those tables are populated.

---

## Exposure management, TVM, cloud, Teams, UEBA, AI (schema catalog)

All names from [schema tables](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables). Most are **hunting / vulnerability** rather than NRT custom detections.

| Table | Area |
| --- | --- |
| `DeviceTvmSoftwareInventory` | Installed software |
| `DeviceTvmSoftwareVulnerabilities` | CVE on devices |
| `DeviceTvmSoftwareVulnerabilitiesKB` | CVE knowledge base |
| `DeviceTvmSoftwareEvidenceBeta` | Evidence of software |
| `DeviceTvmSecureConfigurationAssessment` | Secure config assessment |
| `DeviceTvmSecureConfigurationAssessmentKB` | Config KB |
| `DeviceTvmInfoGathering` / `DeviceTvmInfoGatheringKB` | Assessment events |
| `DeviceTvmHardwareFirmware` | Hardware/firmware |
| `DeviceTvmBrowserExtensions` / `DeviceTvmBrowserExtensionsKB` | Browser extensions (preview) |
| `DeviceTvmCertificateInfo` | Device certs (preview) |
| `DeviceBaselineComplianceAssessment` / `KB` / `Profiles` | Baseline compliance (preview) |
| `ExposureGraphNodes` / `ExposureGraphEdges` | Security Exposure Management graph |
| `CloudAuditEvents` | Defender for Cloud audit |
| `CloudDnsEvents` | Cloud DNS |
| `CloudProcessEvents` | Defender for Containers process (preview) |
| `CloudStorageAggregatedEvents` | Cloud storage (preview) |
| `CloudPolicyEnforcementEvents` | Policy gating (preview) |
| `BehaviorInfo` / `BehaviorEntities` | MDA / UEBA behaviors (preview; not GCC) |
| `DataSecurityEvents` / `DataSecurityBehaviors` | Purview (preview) |
| `DisruptionAndResponseEvents` | Automatic attack disruption (preview) |
| `MessageEvents` / `MessagePostDeliveryEvents` / `MessageUrlInfo` | Teams messages |
| `CallActivityEvents` | Teams calls |
| `AgentsInfo` / `AIAgentsInfo` | AI agents (preview) |

---

## Common MDE columns (process/network detections)

From [DeviceProcessEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceprocessevents-table) and siblings (not exhaustive):

`Timestamp`, `DeviceId`, `DeviceName`, `ReportId`, `ActionType`, `FileName`, `FolderPath`, `SHA1`, `SHA256`, `MD5`, `ProcessId`, `ProcessCommandLine`, `ProcessIntegrityLevel`, `AccountName`, `AccountDomain`, `AccountSid`, `AccountUpn`, `AccountObjectId`, `InitiatingProcess*` (file, command line, SHA1, account, parent), `RemoteIP`, `RemoteUrl`, `RemotePort`, `RemoteDeviceName`, `LocalIP`, `LocalPort`, `Protocol`, `AdditionalFields`.

---

## Count

| Group | Tables listed |
| --- | --- |
| Endpoint | 10 |
| Alert | 2 |
| Email / URL / campaign | 7 |
| Identity | 6 |
| Cloud / Entra / Graph / OAuth | 7 |
| TVM / baseline / exposure / cloud / Teams / UEBA / AI | **30+** |
| **Schema catalog total (Learn list)** | **~65** |
