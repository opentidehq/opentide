# reviewed_before_modified

A rule's `metadata.reviewed` date is earlier than its `metadata.modified` date: the rule changed after its last review.

Severity: warning. Reported by `opentide lint` (metadata check). `opentide validate` does not report it, and nothing is compared when either date is missing or is not a valid date (the `schema` check reports those).

## Example

```yaml
metadata:
  modified: 2026-11-20
  reviewed: 2026-09-01   # earlier than modified
```

## How to fix

Review the rule again, then set `metadata.reviewed` to the day of that review (the same day as `modified`, or later). The comparison is by calendar day, as written: an offset is not applied, and a rule reviewed and modified on one day is not reported. To change the severity, set `severity = "info"` or `"error"` under `[metadata]`, or `reviewed_before_modified = "info"` under `[metadata.codes]`; to stop the warning, set `reviewed_before_modified = "off"` there.
