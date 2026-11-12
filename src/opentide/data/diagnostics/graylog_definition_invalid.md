# graylog_definition_invalid

Graylog refused an event definition, naming the fields at fault.

Severity: error. Reported by `opentide deploy` on a `graylog` block (graylog-1.0). Graylog answered 400 with `{"errors": {<field>: [<message>]}}`: a value it does not accept, such as a stream or notification id that does not exist.

## Example

```text
graylog_definition_invalid: notifications: Notification 65f0c0ffee0123456789abcf doesn't exist
```

## How to fix

Fix the field Graylog names: for an id, the tenant's `stream_ids` or `notification_ids` table.
