# graylog_definition_recreated

The recorded Graylog event definition was gone, so deploy created it again.

Severity: warning. Reported by `opentide deploy` on a `graylog` block (graylog-1.0). `PUT /api/events/definitions/{id}` answered 404: someone deleted the definition in Graylog. Deploy creates it again and replaces the id in `.opentide/states/deployment/`.

## Example

```text
graylog_definition_recreated: the recorded definition no longer exists on the tenant; creating it again
```

## How to fix

Commit the updated deployment state. Delete definitions through a `DELETION` status, not in Graylog.
