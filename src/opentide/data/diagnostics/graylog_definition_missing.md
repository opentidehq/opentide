# graylog_definition_missing

The recorded Graylog event definition was gone when deploy came to disable it.

Severity: warning. Reported by `opentide deploy` on a `graylog` block (graylog-1.0) under `DISABLEMENT`. `PUT` answered 404; there is nothing to disable, so deploy creates nothing and removes the id from `.opentide/states/deployment/`.

## Example

```text
graylog_definition_missing: the recorded definition no longer exists on the tenant; its id is removed
```

## How to fix

Commit the updated deployment state.
