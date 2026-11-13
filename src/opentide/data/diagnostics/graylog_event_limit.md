# graylog_event_limit

A Graylog block's event_limit is out of range, or set on an aggregation.

Severity: error. Reported by `opentide validate` on a `graylog` block (graylog-1.0), at `event_limit`. `event_limit` caps the events one run of a filter creates: an integer from 1 to 1,000. An aggregation creates one event per group and takes none.

## Example

```yaml
configurations:
  graylog:
    event_limit: 5000
```

## How to fix

Set a value from 1 to 1,000, or remove `event_limit` from an aggregation.
