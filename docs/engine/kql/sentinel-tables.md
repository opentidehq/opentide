# Microsoft Sentinel tables used in detections

Sentinel queries Log Analytics tables. The marketplace connector catalog lists **600+** tables (many partner `_CL` custom logs). This inventory covers **first-party and commonly used detection tables**, not every `_CL` connector.

Primary citations:

- [Sentinel tables and associated connectors](https://learn.microsoft.com/azure/sentinel/sentinel-tables-connectors-reference)
- [Azure Monitor Logs table reference](https://learn.microsoft.com/azure/azure-monitor/reference/tables/tables-index)
- [Scheduled analytics rules](https://learn.microsoft.com/azure/sentinel/scheduled-rules-overview)
- [ASIM (normalization)](https://learn.microsoft.com/azure/sentinel/normalization)

Time column for almost all Sentinel tables: **`TimeGenerated`**. Prefer ASIM parsers (`_Im_*` / `im*`) as the query source when writing new analytics so rules survive connector changes.

Custom logs use the `_CL` suffix; NRT custom detections in Defender list several `_CL` tables (Okta, Proofpoint, SAP). [Custom detection rules](https://learn.microsoft.com/defender-xdr/custom-detection-rules)

---

## Microsoft Entra ID / identity (`AAD*`, sign-in, audit)

| Table | Docs | Typical detection use | Citation |
| --- | --- | --- | --- |
| `SigninLogs` | Interactive Entra sign-ins | Failed MFA, impossible travel, legacy auth | [SigninLogs](https://learn.microsoft.com/azure/azure-monitor/reference/tables/signinlogs) |
| `AADNonInteractiveUserSignInLogs` | Non-interactive user sign-ins | Token replay, auth storms | [AADNonInteractiveUserSignInLogs](https://learn.microsoft.com/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs) |
| `AADServicePrincipalSignInLogs` | Service principal sign-ins | SP credential abuse | [AADServicePrincipalSignInLogs](https://learn.microsoft.com/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs) |
| `AADManagedIdentitySignInLogs` | Managed identity sign-ins | Unexpected MI auth | [AADManagedIdentitySignInLogs](https://learn.microsoft.com/azure/azure-monitor/reference/tables/aadmanagedidentitysigninlogs) |
| `ADFSSignInLogs` | AD FS sign-ins | Federation attacks | [ADFSSignInLogs](https://learn.microsoft.com/azure/azure-monitor/reference/tables/adfssigninlogs) |
| `AuditLogs` | Entra audit (directory changes) | Role adds, app consent, PIM | [AuditLogs](https://learn.microsoft.com/azure/azure-monitor/reference/tables/auditlogs) |
| `AADProvisioningLogs` | Provisioning | Rogue sync | [AADProvisioningLogs](https://learn.microsoft.com/azure/azure-monitor/reference/tables/aadprovisioninglogs) |
| `AADUserRiskEvents` | Identity Protection user risk | Risk detections | [AADUserRiskEvents](https://learn.microsoft.com/azure/azure-monitor/reference/tables/aaduserriskevents) |
| `AADRiskyUsers` | Risky user snapshot | Watch risky accounts | [AADRiskyUsers](https://learn.microsoft.com/azure/azure-monitor/reference/tables/aadriskyusers) |
| `AADServicePrincipalRiskEvents` | SP risk events | Compromised SP | [AADServicePrincipalRiskEvents](https://learn.microsoft.com/azure/azure-monitor/reference/tables/aadserviceprincipalriskevents) |
| `AADRiskyServicePrincipals` | Risky SP snapshot | | [AADRiskyServicePrincipals](https://learn.microsoft.com/azure/azure-monitor/reference/tables/aadriskyserviceprincipals) |
| `MicrosoftGraphActivityLogs` | Graph API requests | Consent/graph recon | [MicrosoftGraphActivityLogs](https://learn.microsoft.com/azure/azure-monitor/reference/tables/microsoftgraphactivitylogs) |

NRT-capable (Defender continuous): `AuditLogs`, `SigninLogs` (among others). [Custom detection rules](https://learn.microsoft.com/defender-xdr/custom-detection-rules)

---

## Windows security, syslog, CEF

| Table | Docs | Typical detection use | Citation |
| --- | --- | --- | --- |
| `SecurityEvent` | Windows Security Auditing via AMA/legacy | 4624/4625, 4688, 4104, DC events | [SecurityEvent](https://learn.microsoft.com/azure/azure-monitor/reference/tables/securityevent) |
| `WindowsEvent` | Windows events (AMA XML) | When SecurityEvent is not populated | [WindowsEvent](https://learn.microsoft.com/azure/azure-monitor/reference/tables/windowsevent) |
| `Event` | Legacy Windows event table | Older workspaces | [Event](https://learn.microsoft.com/azure/azure-monitor/reference/tables/event) |
| `Syslog` | Linux syslog | authpriv, sudo, cron | [Syslog](https://learn.microsoft.com/azure/azure-monitor/reference/tables/syslog) |
| `CommonSecurityLog` | CEF (firewalls, Zscaler, Infoblox, …) | Network/proxy/VPN | [CommonSecurityLog](https://learn.microsoft.com/azure/azure-monitor/reference/tables/commonsecuritylog) |
| `DnsEvents` | DNS analytics / solutions | DGA, tunneling | [DnsEvents](https://learn.microsoft.com/azure/azure-monitor/reference/tables/dnsevents) |
| `DnsInventory` | DNS inventory | | [DnsInventory](https://learn.microsoft.com/azure/azure-monitor/reference/tables/dnsinventory) |
| `W3CIISLog` | IIS | Web shells, scanning | [W3CIISLog](https://learn.microsoft.com/azure/azure-monitor/reference/tables/w3ciislog) |

NRT-capable: `SecurityEvent`, `CommonSecurityLog`.

---

## Sentinel / Defender incidents and UEBA

| Table | Docs | Typical detection use | Citation |
| --- | --- | --- | --- |
| `SecurityAlert` | Alerts from Sentinel and connected products | Correlation, suppression hunting | [SecurityAlert](https://learn.microsoft.com/azure/azure-monitor/reference/tables/securityalert) |
| `SecurityIncident` | Sentinel incidents | Incident metrics (not usually a *source* of new detections) | [SecurityIncident](https://learn.microsoft.com/azure/azure-monitor/reference/tables/securityincident) |
| `BehaviorAnalytics` | UEBA | Anomalous logon/peer outliers | [BehaviorAnalytics](https://learn.microsoft.com/azure/azure-monitor/reference/tables/behavioranalytics) |
| `IdentityInfo` | UEBA identity snapshot | Enrichment via `lookup`/`join` | [IdentityInfo](https://learn.microsoft.com/azure/azure-monitor/reference/tables/identityinfo) |
| `Anomalies` | Sentinel ML anomalies | Consume anomaly scores | [Anomalies](https://learn.microsoft.com/azure/azure-monitor/reference/tables/anomalies) |
| `Watchlist` | Watchlist items (also `_GetWatchlist()`) | IOC allow/deny lists | [Watchlists](https://learn.microsoft.com/azure/sentinel/watchlists) |
| `ThreatIntelligenceIndicator` | Classic TI | Match IP/domain/hash | [ThreatIntelligenceIndicator](https://learn.microsoft.com/azure/azure-monitor/reference/tables/threatintelligenceindicator) |
| `ThreatIntelIndicators` | Newer TI schema | Same | [ThreatIntelIndicators](https://learn.microsoft.com/azure/azure-monitor/reference/tables/threatintelindicators) |
| `LAQueryLogs` | Log Analytics query audit | Suspicious hunting by attackers | [Audit Sentinel queries](https://learn.microsoft.com/azure/sentinel/audit-sentinel-data) |

NRT-capable: `SecurityAlert`.

---

## Azure activity, diagnostics, firewall (`Azure*`, `AZFW*`)

| Table | Docs | Typical detection use | Citation |
| --- | --- | --- | --- |
| `AzureActivity` | ARM control-plane activity | Role assignments, diagnostic-setting deletes | [AzureActivity](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azureactivity) |
| `AzureDiagnostics` | Multi-resource diagnostics (Key Vault, NSG, Firewall legacy, WAF, …) | KV access, NSG flows (legacy) | [AzureDiagnostics](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azurediagnostics) |
| `AzureMetrics` | Resource metrics | Rare in detections | [AzureMetrics](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azuremetrics) |
| `AZFWNetworkRule` | Azure Firewall network rules | Allowed/denied flows | [AZFWNetworkRule](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azfwnetworkrule) |
| `AZFWApplicationRule` | App rules | | [AZFWApplicationRule](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azfwapplicationrule) |
| `AZFWNatRule` | DNAT | | [AZFWNatRule](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azfwnatrule) |
| `AZFWDnsQuery` | Firewall DNS proxy | | [AZFWDnsQuery](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azfwdnsquery) |
| `AZFWIdpsSignature` | IDPS hits | | [AZFWIdpsSignature](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azfwidpssignature) |
| `AZFWThreatIntel` | Firewall TI | | [AZFWThreatIntel](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azfwthreatintel) |
| `AZFWFatFlow` / `AZFWFlowTrace` / `AZFWInternalFqdnResolutionFailure` | Extra FW logs | Hunting | [AZFWFatFlow](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azfwfatflow) |
| `StorageBlobLogs` / `StorageFileLogs` / `StorageQueueLogs` / `StorageTableLogs` | Storage analytics | Anonymous blob access | [StorageBlobLogs](https://learn.microsoft.com/azure/azure-monitor/reference/tables/storagebloblogs) |
| `NetworkAccessTraffic` | Global Secure Access / Entra Private Access | | [NetworkAccessTraffic](https://learn.microsoft.com/azure/azure-monitor/reference/tables/networkaccesstraffic) |

NRT-capable: `AzureActivity`.

---

## AWS (`AWS*`)

| Table | Docs | Typical detection use | Citation |
| --- | --- | --- | --- |
| `AWSCloudTrail` | CloudTrail management/data events | Console login, IAM, S3 | [AWSCloudTrail](https://learn.microsoft.com/azure/azure-monitor/reference/tables/awscloudtrail) |
| `AWSGuardDuty` | GuardDuty findings | Correlate AWS threats | [AWSGuardDuty](https://learn.microsoft.com/azure/azure-monitor/reference/tables/awsguardduty) |
| `AWSVPCFlow` | VPC flow logs | Beaconing, port scans | [AWSVPCFlow](https://learn.microsoft.com/azure/azure-monitor/reference/tables/awsvpcflow) |
| `AWSCloudWatch` | CloudWatch | | [AWSCloudWatch](https://learn.microsoft.com/azure/azure-monitor/reference/tables/awscloudwatch) |
| `AWSWAF` | AWS WAF | | [AWSWAF](https://learn.microsoft.com/azure/azure-monitor/reference/tables/awswaf) |
| `AWSNetworkFirewallFlow` | Network Firewall | | [AWSNetworkFirewallFlow](https://learn.microsoft.com/azure/azure-monitor/reference/tables/awsnetworkfirewallflow) |
| `AWSRoute53Resolver` | Route 53 resolver | | [AWSRoute53Resolver](https://learn.microsoft.com/azure/azure-monitor/reference/tables/awsroute53resolver) |
| `AWSS3ServerAccess` | S3 access | | [AWSS3ServerAccess](https://learn.microsoft.com/azure/azure-monitor/reference/tables/awss3serveraccess) |
| `AWSSecurityHubFindings` | Security Hub | | [AWSSecurityHubFindings](https://learn.microsoft.com/azure/azure-monitor/reference/tables/awssecurityhubfindings) |

NRT-capable: `AWSCloudTrail`, `AWSGuardDuty`.

---

## GCP

| Table | Typical use | Citation hub |
| --- | --- | --- |
| `GCPAuditLogs` | Admin activity / data access | [GCPAuditLogs](https://learn.microsoft.com/azure/azure-monitor/reference/tables/gcpauditlogs) |
| `GCPVPCFlow` | VPC flows | [GCPVPCFlow](https://learn.microsoft.com/azure/azure-monitor/reference/tables/gcpvpcflow) |
| `GCPDNS` `GCPIAM` `GCPIDS` `GCPCloudSQL` `GCPComputeEngine` `GCPCloudRun` `GCPLoadBalancer` / `GCPCDN` `GCPNAT` `GCPMonitoring` `GCPResourceManager` `GCPApigee` `GKEAudit` | Product-specific | [Sentinel table-connector map](https://learn.microsoft.com/azure/sentinel/sentinel-tables-connectors-reference) |

NRT-capable: `GCPAuditLogs`.

---

## Microsoft 365 / Office / Power Platform

| Table | Docs | Typical detection use | Citation |
| --- | --- | --- | --- |
| `OfficeActivity` | Unified Audit Log (Exchange, SharePoint, Teams, Azure AD ops in UAL) | Inbox rules, sharing, eDiscovery | [OfficeActivity](https://learn.microsoft.com/azure/azure-monitor/reference/tables/officeactivity) |
| `CloudAppEvents` | Defender for Cloud Apps / XDR | OAuth, session, SaaS | [CloudAppEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-cloudappevents-table) |
| `EmailEvents` | Defender for Office 365 | Phish/malware delivery | See [defender-tables.md](defender-tables.md) |
| `Dynamics365Activity` | D365 audit | | [Dynamics365Activity](https://learn.microsoft.com/azure/azure-monitor/reference/tables/dynamics365activity) |
| `PowerBIActivity` | Power BI audit | | [PowerBIActivity](https://learn.microsoft.com/azure/azure-monitor/reference/tables/powerbiactivity) |
| `PowerAutomateActivity` / `PowerPlatformAdminActivity` / `ProjectActivity` | Power Platform | | [PowerAutomateActivity](https://learn.microsoft.com/azure/azure-monitor/reference/tables/powerautomateactivity) |
| `MicrosoftPurviewInformationProtection` / `PurviewDataSensitivityLogs` | DLP / labeling | | [MicrosoftPurviewInformationProtection](https://learn.microsoft.com/azure/azure-monitor/reference/tables/microsoftpurviewinformationprotection) |
| `CopilotActivity` | Microsoft Copilot | Prompt/activity audit | [CopilotActivity](https://learn.microsoft.com/azure/azure-monitor/reference/tables/copilotactivity) |
| `OpenAIAuditLogs` | Azure OpenAI | | [Sentinel connectors](https://learn.microsoft.com/azure/sentinel/sentinel-tables-connectors-reference) |

NRT-capable: `OfficeActivity`.

---

## Defender XDR tables in the Sentinel workspace

When the Microsoft Defender XDR connector is enabled, hunting tables appear in the workspace (same names as Defender). Use them in Sentinel analytics like any other table. Full column docs: [defender-tables.md](defender-tables.md).

Most common in **Sentinel** rule packs:

`DeviceEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, `DeviceImageLoadEvents`, `DeviceInfo`, `DeviceNetworkInfo`, `EmailEvents`, `IdentityLogonEvents`, `IdentityDirectoryEvents`, `IdentityQueryEvents`, `CloudAppEvents`, `AlertEvidence`, `UrlClickEvents`, `AADSignInEventsBeta`

---

## ASIM normalized tables / parsers

Citation: [ASIM](https://learn.microsoft.com/azure/sentinel/normalization)

| Schema | Native table (when used) | Parser functions (typical) |
| --- | --- | --- |
| Audit | `ASimAuditEventLogs` | `_Im_AuditEvent` |
| Authentication | `ASimAuthenticationEventLogs` | `_Im_Authentication` / `imAuthentication` |
| DHCP | `ASimDhcpEventLogs` | `_Im_DhcpEvent` |
| DNS | `ASimDnsActivityLogs` | `_Im_Dns` |
| File | `ASimFileEventLogs` | `_Im_FileEvent` |
| Network session | `ASimNetworkSessionLogs` | `_Im_NetworkSession` |
| Process | `ASimProcessEventLogs` | `_Im_ProcessEvent` |
| Registry | `ASimRegistryEventLogs` | `_Im_RegistryEvent` |
| User management | `ASimUserManagementActivityLogs` | `_Im_UserManagement` |
| Web session | `ASimWebSessionLogs` | `_Im_WebSession` |

Microsoft recommends ASIM parsers as analytics **sources** instead of a single native table. [Scheduled analytics rules](https://learn.microsoft.com/azure/sentinel/scheduled-rules-overview)

---

## Operational / agent (sometimes used in detections)

| Table | Use | Citation |
| --- | --- | --- |
| `Heartbeat` | Missing heartbeat / agent health (availability rules) | [Heartbeat](https://learn.microsoft.com/azure/azure-monitor/reference/tables/heartbeat) |
| `Usage` | Ingestion volume | [Usage](https://learn.microsoft.com/azure/azure-monitor/reference/tables/usage) |
| `Operation` | Workspace operations | [Operation](https://learn.microsoft.com/azure/azure-monitor/reference/tables/operation) |
| `Update` / `UpdateSummary` | Update Compliance | [Update](https://learn.microsoft.com/azure/azure-monitor/reference/tables/update) |
| `Perf` / `InsightsMetrics` | Performance — rare in security detections | [Perf](https://learn.microsoft.com/azure/azure-monitor/reference/tables/perf) |

---

## Partner tables frequently seen in NRT / content hub

Not exhaustive. Connector map: [Sentinel tables](https://learn.microsoft.com/azure/sentinel/sentinel-tables-connectors-reference)

| Table | Product |
| --- | --- |
| `Okta_CL` / `OktaV2_CL` / `OktaSSO` | Okta |
| `ProofpointPOD` / `ProofPointTAPClicksPermitted_CL` / `ProofPointTAPMessagesDelivered_CL` | Proofpoint |
| `ABAPAuditLog` / `ABAPAuditLog_C` / SAP `*_CL` | SAP |
| `GCPAuditLogs` | GCP |
| `CrowdStrikeAlerts` / `CrowdStrikeReplicatorV2` | CrowdStrike |
| `Cisco_Umbrella_*_CL` | Cisco Umbrella |
| `Qualys*` / `Rapid7*` | VM scanners |

---

## Detection query notes

- Filter on **`TimeGenerated`** (or `ingestion_time()` when matching custom-detection lookback). Do not depend on `now()` inside a **query function** for cache-busting in the Sentinel scheduled engine — pass lookback via `ago()`.
- Entity mapping uses columns such as `Account`, `AccountName`, `UserPrincipalName`, `IpAddress`, `Computer`, `HostName`, `Url`, `FileHash`. [Analytics rule entity mapping](https://learn.microsoft.com/azure/sentinel/map-data-fields-to-entities)
- `search *` / `union *` are **invalid** in scheduled analytics. Name tables explicitly.

## Count

| Class | Count on this page |
| --- | --- |
| Named first-party / common tables | **~95** |
| ASIM native tables | **10** |
| Full connector catalog (not duplicated here) | **600+** including `_CL` |
