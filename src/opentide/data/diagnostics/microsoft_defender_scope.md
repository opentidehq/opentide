# microsoft_defender_scope

A Microsoft Defender block's `scope` is not a non-empty list of device group names.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `microsoft_defender` block (microsoft-defender-1.0). `scope` is `{device_groups: [...]}`. With no `scope` the rule applies to every device; an empty list would apply to none. The finding is on `scope`.

## Example

```yaml
configurations:
  microsoft_defender:
    scope:
      device_groups: []
```

## How to fix

List the device groups, or remove `scope` to cover every device.
