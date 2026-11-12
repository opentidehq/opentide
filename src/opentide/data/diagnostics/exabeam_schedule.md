# exabeam_schedule

A `schedule` recurrence is not one Exabeam takes.

Severity: error. Reported by `opentide validate` on an `exabeam` block (exabeam-1.0). Each recurrence has `every` (`day`, `week`, `month` or `days`), `from` and `to` as UTC `HH:MMZ`, and exactly the day keys its `every` takes: `week` takes `days` (weekday names), `month` takes `days` (1 to 31) and `last_day`, `days` takes `first` and `last` (weekday names).

## Example

```yaml
schedule:
  - every: week
    days: [mon]
    from: "08:00Z"
    to: "18:00Z"
```

## How to fix

Write weekday names in full and lower case (`monday`), times as `HH:MMZ` in quotes, and only the keys the recurrence takes.
