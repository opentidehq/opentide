# microsoft_defender_column

A Microsoft Defender column name is blank or not a string.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `microsoft_defender` block (microsoft-defender-1.0). Entity fields, action columns and custom detail values name a column of the query's output, sent verbatim (`DeviceId`). Whether the query returns the column is `microsoft_defender_column_not_in_output`, which the analysis engine checks offline against the query's inferred output. The finding is on the field.

## Example

```yaml
configurations:
  microsoft_defender:
    entities:
      hosts:
        - device_id: ""
```

## How to fix

Name the result column (`device_id: DeviceId`), or remove the field.
