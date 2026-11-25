# microsoft_defender_entity_mapping

A Microsoft Defender entity mapping is empty, is not a mapping, or names a field its kind does not have.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `microsoft_defender` block (microsoft-defender-1.0). Each kind holds a list of mappings; a mapping names at least one of its kind's fields (`hosts`: `device_id`, `name`, `dns_domain`, `netbios_name`, `nt_domain`), each a result column. The finding is on `entities.<kind>.<N>`.

## Example

```yaml
configurations:
  microsoft_defender:
    entities:
      hosts:
        - device_id: DeviceId
          sid: AccountSid
```

## How to fix

Move the field to the kind that has it (`sid` is an `accounts` field), or remove it.
