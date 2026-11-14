# graylog_all_streams

A Graylog definition names no stream, so it searches every stream.

Severity: warning. Reported by `opentide validate` on a `graylog` block (graylog-1.0); never fails a rule. The block sets no `streams` and no `stream_categories`, and a tenant it deploys to sets no default `streams`: Graylog then searches every stream the token's user can read.

## Example

```yaml
configurations:
  graylog:
    query: EventID:1
```

## How to fix

Set `streams` on the block, or default `streams` on the tenant's `[tenants.setup]`.
