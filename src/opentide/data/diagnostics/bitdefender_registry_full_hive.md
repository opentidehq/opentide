# bitdefender_registry_full_hive

A `Registry.Key` criterion starts with a full hive name, which GravityZone accepts and never matches.

Severity: warning. Reported by `opentide validate` and `opentide lint` (its `queries` check) on a `bitdefender` block (bitdefender-1.0). It is an advisory: the rule validates and deploys, but GravityZone stores registry keys under the short hive names, so `HKEY_LOCAL_MACHINE\…` never triggers.

## Example

```yaml
configurations:
  bitdefender:
    detection:
      target: registry
      criteria:
        - field: Registry.Key
          contains: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run*
```

## How to fix

Write the short hive name, as in `HKLM\Software\Microsoft\Windows\CurrentVersion\Run*`: `HKLM`, `HKCU`, `HKCR` or `HKCC`; `HKU` for a user's hive, `HKEY_USERS\<SID>…`; and `HKLU` for any other `HKEY_USERS\…` key. The hive name is compared case-insensitively.
