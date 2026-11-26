# microsoft_defender_entity_identifier

A Microsoft Defender entity mapping lacks an identifier Graph requires of its kind.

Severity: error. Reported by `opentide validate` (its `schema` check) and by an editor running `opentide lsp start`, on a `microsoft_defender` block (microsoft-defender-1.0). Graph checks a rule's entity mappings when the rule is created and each time it is enabled, not while it is disabled, so without this check a disabled rule with a bad mapping fails on the deploy that turns it back on. The finding is on `entities.<kind>.<N>`, and its message names the missing field, Graph's identifier for it and the property it is sent as.

One rule is enforced: a `registry_values` mapping sets `key` (identifier `RegKey`, sent as `keyColumn`). Without it Graph answers:

```text
HTTP 400 · Entity mapping for type 'RegistryValue' does not include a required identifier. Supported identifiers: RegKey | Name
```

The other kinds need any one of their fields (`microsoft_defender_entity_mapping`): Microsoft documents no further requirement for them, and none has been observed.

## Example

```yaml
configurations:
  microsoft_defender:
    entities:
      registry_values:
        - value_name: RegistryValueName
```

## How to fix

Map the missing field to the result column that holds it, and have the query return that column: `registry_values: [{key: RegistryKey, value_name: RegistryValueName}]`.
