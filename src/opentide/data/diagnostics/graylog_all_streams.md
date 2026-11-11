# graylog_all_streams

A Graylog definition names no stream, so it searches every stream.

Severity: warning. Reported by `opentide validate` on a `graylog` block (graylog-1.0); never fails a rule. Neither the block nor a tenant it deploys to sets `streams`, and the block sets no `stream_categories`: Graylog then searches every stream the token's user can read.

## Example

```yaml
configurations:
  graylog:
    query: EventID:1
```

## How to fix

Set `streams` on the block, or default `streams` on the tenant's `[tenants.setup]`.
