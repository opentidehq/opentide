# microsoft_defender_isolation_type

A Microsoft Defender `isolate_devices` target's `isolation_type` is not `full` or `selective`.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `microsoft_defender` block (microsoft-defender-1.0). It is sent as Graph's `isolationType`. The finding is on `actions.isolate_devices.<N>.isolation_type`.

## Example

```yaml
configurations:
  microsoft_defender:
    actions:
      isolate_devices:
        - device_id: DeviceId
          isolation_type: Full
```

## How to fix

Write `full` or `selective`, lower case.
