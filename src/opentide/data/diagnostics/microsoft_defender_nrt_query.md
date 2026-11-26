# microsoft_defender_nrt_query

A Microsoft Defender rule runs continuously (`frequency: NRT`), and its query is one Microsoft documents NRT cannot run.

Severity: warning. Reported by the analysis engine on the KQL query of a `microsoft_defender` block whose `schedule.frequency` is `NRT`: `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it; `opentide validate` does not fail on it. Microsoft's [custom detection docs](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules) (read 2026-11-26) say "You can run a query continuously as long as: The query references one table only. [...] The query doesn't use joins, unions, or the externaldata operator. The query doesn't include any comments line or information.", list the tables near real-time detections support, and leave out `EmailEvents`' `LatestDeliveryLocation` and `LatestDeliveryAction` columns. Each finding is where the query breaks one of these: a second table, a table off the list, each `join`, `union` and `externaldata`, the first comment (the message counts them), or an excluded `EmailEvents` column.

The check is conservative. A query with a syntax error, a table read through a function or another database's table, and the docs' list of supported KQL operators are not judged. A `let` or a parameter name is not a table. What Graph does with such a rule is not documented.

The tables: `AlertEvidence`, `CloudAppEvents`, `DeviceEvents`, `DeviceFileCertificateInfo`, `DeviceFileEvents`, `DeviceImageLoadEvents`, `DeviceLogonEvents`, `DeviceNetworkEvents`, `DeviceNetworkInfo`, `DeviceInfo`, `DeviceProcessEvents`, `DeviceRegistryEvents`, `EmailAttachmentInfo`, `EmailEvents`, `EmailPostDeliveryEvents`, `EmailUrlInfo`, `IdentityDirectoryEvents`, `IdentityLogonEvents`, `IdentityQueryEvents` and `UrlClickEvents` from Defender XDR; `ABAPAuditLog_C`, `ABAPChangeDocsLog_CL`, `AuditLogs`, `AWSCloudTrail`, `AWSGuardDuty`, `AzureActivity`, `CommonSecurityLog`, `GCPAuditLogs`, `MicrosoftGraphActivityLogs`, `OfficeActivity`, `Okta_CL`, `OktaV2_CL`, `ProofpointPOD`, `ProofPointTAPClicksPermitted_CL`, `ProofPointTAPMessagesDelivered_CL`, `SecurityAlert`, `SecurityEvent` and `SigninLogs` from Microsoft Sentinel.

## Example

```yaml
configurations:
  microsoft_defender:
    schedule:
      frequency: NRT
    query: |
      // PowerShell on servers
      DeviceProcessEvents
      | where FileName =~ "powershell.exe"
      | join (DeviceInfo | where DeviceType == "Server") on DeviceId
```

## How to fix

Move comments to the rule's description, and filter one table from the list without a join, a union or `externaldata`. A detection that needs more than that runs on a schedule: `frequency: 1H`, `3H`, `12H` or `24H`.
