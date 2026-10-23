# deployment_state_shape

A deployment state shard is not the JSON shape opentide writes.

Severity: error. Reported by `opentide validate` (schema check).

## Example

```json
{"object_uuid": "00000000-0000-4000-8003-000000000001"}   # no platforms object
```

## How to fix

Restore the shard from version control, or delete it and let the next deploy write it again. A shard is `.opentide/states/deployment/<uuid>.json` with `object_uuid` and a `platforms` object of tenant to vendor id.
