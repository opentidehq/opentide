# microsoft_defender_impacted_asset_identifier

A Microsoft Defender device, user or mailbox mapping sets none of the identifiers Defender names an impacted asset by.

Severity: warning. Reported by `opentide validate`, `opentide lint` (its `queries` check) and an editor running `opentide lsp start`, on a `microsoft_defender` block (microsoft-defender-1.0). `hosts`, `accounts` and `mailboxes` are the alert's impacted assets, and Defender identifies each by a strong identifier: a device by `device_id` (`DeviceId`) or `name` (`DeviceName`, `RemoteDeviceName`); a user by `aad_user_id` (`AccountObjectId`), `sid` (`AccountSid`, `InitiatingProcessAccountSid`) or `upn` (`AccountUpn`, `InitiatingProcessAccountUpn`); a mailbox by `primary_address` (`RecipientEmailAddress`, `SenderFromAddress`). A mapping with only weak fields (an account's `name` or `nt_domain`, a device's `netbios_name` or `dns_domain`) may leave the alert without an impacted asset to triage, correlate or act on. The finding is on `entities.<kind>.<N>`. It is an advisory: the rule validates and deploys.

## Example

```yaml
configurations:
  microsoft_defender:
    entities:
      accounts:
        - name: AccountName
          nt_domain: AccountDomain
```

## How to fix

Add an identifier field to the mapping, and have the query return its column: `accounts: [{upn: AccountUpn, name: AccountName}]`.
