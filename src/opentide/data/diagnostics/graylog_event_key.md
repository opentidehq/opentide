# graylog_event_key

A Graylog event_key item is not an event field of the block.

Severity: error. Reported by `opentide validate` on a `graylog` block (graylog-1.0), at `event_key`. Graylog builds the event key from event fields, and refuses a key field `event_fields` does not define.

## Example

```yaml
configurations:
  graylog:
    event_fields: {host: source}
    event_key: user
```

## How to fix

Add the field to `event_fields`, or key on one that is there.
