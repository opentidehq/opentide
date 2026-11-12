# graylog_priority_collapsed

Graylog before 7.1 has no Informational priority: the definition is sent as Low.

Severity: warning. Reported by `opentide deploy` on a `graylog` block (graylog-1.0). The priority comes from the block's `priority`, else `response.alert_severity`. Graylog 7.1 added priority 0 (Informational); before it, deploy sends 1 (Low).

## Example

```text
graylog_priority_collapsed: Graylog 7.0.16 has no Informational priority: sent as Low (1)
```

## How to fix

Upgrade the tenant to 7.1 or later, or set `priority: Low` on the block.
