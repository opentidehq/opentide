# graylog_forbidden

Graylog refused a request for want of a permission.

Severity: error. Reported by `opentide deploy` on a `graylog` block (graylog-1.0). Graylog answered 403; the rule fails and the next one is sent. The token's user needs `eventdefinitions:create`, `eventdefinitions:read`, `eventdefinitions:edit` and `eventdefinitions:delete`, and `streams:read` on every stream a definition names.

## Example

```text
graylog_forbidden: POST /api/events/definitions?schedule=true was refused (HTTP 403)
```

## How to fix

Grant the token's user the permissions, most often `streams:read` on the definition's streams.
