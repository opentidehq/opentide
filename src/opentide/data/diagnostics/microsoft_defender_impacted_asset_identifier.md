# microsoft_defender_impacted_asset_identifier

A Microsoft Defender device or user mapping sets no strong identifier of its impacted asset.

Severity: warning, which `opentide validate --strict` reports without failing. Reported by `opentide validate`, `opentide lint` (its `queries` check) and an editor running `opentide lsp start`, on a `microsoft_defender` block (microsoft-defender-1.0). `hosts` and `accounts` map the alert's impacted devices and users. Microsoft's custom detection page lists the result columns its rule wizard maps to an impacted asset by itself, each a strong identifier: for a device `DeviceId` (`device_id`) or `DeviceName`, `RemoteDeviceName` (`name`); for a user `AccountObjectId` (`aad_user_id`), `AccountSid`, `InitiatingProcessAccountSid` (`sid`) or `AccountUpn`, `InitiatingProcessAccountUpn` (`upn`). Microsoft Sentinel's entity reference adds the strong combinations: a user's `name` with `nt_domain`, `dns_domain` or `upn_suffix`, and a device's `netbios_name` with `nt_domain` or `dns_domain`. A mapping with none of these (an account's `name` alone, a device's `dns_domain` alone) may not tell Defender which device or user the alert is about. Neither page says Graph refuses such a mapping, so the rule validates and deploys. The finding is on `entities.<kind>.<N>`.

## Example

```yaml
configurations:
  microsoft_defender:
    entities:
      accounts:
        - name: AccountName
```

## How to fix

Add an identifier to the mapping, and have the query return its column: `accounts: [{upn: AccountUpn}]`, or `accounts: [{name: AccountName, nt_domain: AccountDomain}]`.
