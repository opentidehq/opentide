# exabeam_correlation_window

`correlation.within` is shorter than the longest sequence window.

Severity: warning. Reported by `opentide validate` and `opentide lint` (its `queries` check) on an `exabeam` block (exabeam-1.0). Exabeam's guide asks for a correlation window at least as long as the longest `threshold.within`, or the correlation may never see a sequence's condition met. It is an advisory: the rule validates and deploys.

## Example

```yaml
sequences:
  - query: activity_type:"app-login" AND outcome:"fail"
    threshold: {function: count, operator: more_than, value: 10, within: 1h}
  - query: activity_type:"app-login" AND outcome:"success"
correlation:
  within: 15m
```

## How to fix

Make `correlation.within` at least the longest `threshold.within` (`1h` here).
