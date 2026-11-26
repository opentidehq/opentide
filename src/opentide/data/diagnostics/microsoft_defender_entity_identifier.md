# microsoft_defender_entity_identifier

A Microsoft Defender entity mapping lacks an identifier Graph requires of its kind.

Severity: error. Reported by `opentide validate` (its `schema` check) and by an editor running `opentide lsp start`, on a `microsoft_defender` block (microsoft-defender-1.0). Graph checks a rule's mappings when it creates the rule and each time it enables it, but not on an update to a disabled rule (#1884); whether it checks a rule created disabled is not confirmed. So a disabled rule with a bad mapping can sit in the tenant and fail on the deploy that enables it. The finding is on `entities.<kind>.<N>`, and its message names the missing field, Graph's identifier for it and the property it is sent as.

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
