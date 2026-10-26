# external_id_shape

A vendor rule id in deployment state has the wrong form.

Severity: error. Reported by `opentide validate` (schema check).

## Example

```json
{"object_uuid": "…", "platforms": {"defender_for_endpoint": {"prod": "-12"}}}
```

## How to fix

Write the id the platform returned. Defender and SentinelOne ids are canonical decimal integers (no sign, no leading zeroes); an id is never empty. A deploy writes these shards; edit them by hand only to repair one.
