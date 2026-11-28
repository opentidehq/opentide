# microsoft_defender_action_target

A Microsoft Defender automated action has no target, or a target is empty or names a field its action does not take.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `microsoft_defender` block (microsoft-defender-1.0). Each action holds a non-empty list of targets; a target names at least one of its action's fields, and `device_groups`, when set, is a non-empty list of device group names. The finding is on `actions.<action>.<N>`, or on its `device_groups`.

## Example

```yaml
configurations:
  microsoft_defender:
    actions:
      block_files:
        - sha256: SHA256
          device_id: DeviceId
```

## How to fix

Keep only the action's fields: `block_files` takes `sha1`, `sha256` and `device_groups`.
