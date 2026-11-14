# graylog_alias_unknown

A Graylog block names a stream or notification alias the tenant does not define.

Severity: error. Reported by `opentide deploy` on a `graylog` block (graylog-1.0), before any call for that rule, and by `opentide deploy --dry-run`. Blocks name streams and notifications by alias; each tenant maps the aliases to ids in `stream_ids` and `notification_ids`.

## Example

```text
graylog_alias_unknown: tenant 'graylog-prod': stream alias(es) sysmon are not in the tenant's stream_ids table
```

## How to fix

Add the alias to the tenant's table in `platforms/graylog.toml`, or change the block.
