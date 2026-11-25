# microsoft_defender_action_kind

A key of a Microsoft Defender block's `actions` is not an automated action.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `microsoft_defender` block (microsoft-defender-1.0). The actions are Graph's sixteen, such as `isolate_devices`, `collect_investigation_packages`, `block_files`, `disable_users` and `soft_delete_emails`. The finding is on `actions.<action>`.

## Example

```yaml
configurations:
  microsoft_defender:
    actions:
      isolate_device:
        - device_id: DeviceId
```

## How to fix

Use the action's name (`isolate_devices`).
