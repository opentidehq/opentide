# graylog_event_field

A Graylog event field has an invalid name or value.

Severity: error. Reported by `opentide validate` on a `graylog` block (graylog-1.0), at `event_fields.<name>`. A name matches `[A-Za-z0-9_.@-]+`. A value is a bare message field name (copied from the message that fired the event), a string containing `${` (a Graylog template), `{template: ...}`, or `{lookup: {table, key_field}}`.

## Example

```yaml
configurations:
  graylog:
    event_fields:
      family: two words
```

## How to fix

Write constant text as `{template: "two words"}`, or name a message field.
