# graylog_definition_in_use

Graylog refuses to delete an event definition another one depends on.

Severity: error. Reported by `opentide deploy` on a `graylog` block (graylog-1.0) under `DELETION`. Another definition (a correlation) depends on this one, so Graylog keeps it, and the binding stays.

## Example

```text
graylog_definition_in_use: another definition depends on this one: ...
```

## How to fix

Remove or change the dependent definitions named in the message, then deploy again.
