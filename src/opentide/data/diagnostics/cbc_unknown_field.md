# cbc_unknown_field

A field in a Carbon Black Cloud query is one or two letters away from a Carbon Black process search field, and is not that field.

Severity: warning. Reported by the query checks and the language server on `configurations.carbon_black_cloud.query`, and on hunts whose `system` is `carbon_black_cloud`, at the field name, with the field it is close to as the suggestion. The field list is the engine's Carbon Black process search catalog. A field far from every catalog field is not reported, because the catalog may not list it.

## Example

```text
`process_nmae` is not a Carbon Black Cloud process search field; did you mean `process_name`?
```

## How to fix

Use the suggested field (`process_name:cmd.exe`). If the field is right and Carbon Black accepts it, `opentide validate query --live` confirms it against the tenant; report the missing field to the language server's catalog (`catalogs/carbon_black/fields.toml`).
