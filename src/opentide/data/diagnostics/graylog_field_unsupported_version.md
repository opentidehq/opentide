# graylog_field_unsupported_version

A Graylog block sets a field the tenant's version cannot take.

Severity: warning. Reported by `opentide deploy` on a `graylog` block (graylog-1.0). `summary` (the event summary template) needs Graylog 7.1, and block `tags` need 7.2. Deploy leaves the field out of the request rather than let Graylog 6.3 drop it silently or 7.x refuse it.

## Example

```text
graylog_field_unsupported_version: summary is left out: Graylog 6.3.5 has no event summary template (7.1 and later)
```

## How to fix

Upgrade the tenant, or remove the field from the block.
