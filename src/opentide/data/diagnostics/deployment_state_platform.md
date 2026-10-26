# deployment_state_platform

A deployment state shard names a platform that stores no external ids.

Severity: error. Reported by `opentide validate` (schema check).

## Example

```json
{"object_uuid": "…", "platforms": {"splunk": {"prod": "…"}}}
```

## How to fix

Remove that platform from the shard. Only the platforms the message lists keep vendor ids in deployment state.
