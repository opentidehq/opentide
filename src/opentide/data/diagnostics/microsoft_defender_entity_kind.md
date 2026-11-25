# microsoft_defender_entity_kind

A key of a Microsoft Defender block's `entities` is not an entity kind.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `microsoft_defender` block (microsoft-defender-1.0). The kinds are Graph's seventeen: `hosts`, `accounts`, `mailboxes`, `files`, `processes`, `ips`, `urls`, `dns`, `registry_values`, `mail_messages`, `mail_clusters`, `cloud_applications`, `oauth_applications`, `security_groups`, `azure_resources`, `amazon_resources`, `google_cloud_resources`. The finding is on `entities.<kind>`.

## Example

```yaml
configurations:
  microsoft_defender:
    entities:
      devices:
        - device_id: DeviceId
```

## How to fix

Use the kind's name (`hosts`, not `devices`).
