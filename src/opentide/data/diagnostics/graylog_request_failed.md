# graylog_request_failed

A Graylog request failed for a reason the failure table does not name.

Severity: error. Reported by `opentide deploy` on a `graylog` block (graylog-1.0): an answer that is not 2xx and none of 400 with field errors, 401, 403, 404 on update, an immutable entity or a definition in use, such as a 500.

## Example

```text
graylog_request_failed: PUT /api/events/definitions/65f1c0de2a3b4c5d6e7f8091?schedule=true: HTTP 500: ...
```

## How to fix

Read Graylog's message and server log, then deploy again.
