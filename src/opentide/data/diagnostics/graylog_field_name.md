# graylog_field_name

A Graylog aggregation groups by a name that is not a field name.

Severity: error. Reported by `opentide validate` on a `graylog` block (graylog-1.0), at `aggregation.group_by`. A Graylog field name matches `[A-Za-z0-9_.@-]+`.

## Example

```yaml
configurations:
  graylog:
    aggregation:
      group_by: [src ip]
      condition: count() > 1
```

## How to fix

Group by the field's real name (`src_ip`).
