# exabeam_correlation_window

`correlation.within` is not more than the time the ordered sequences need.

Severity: warning. Reported by `opentide validate` and `opentide lint` (its `queries` check) on an `exabeam` block with two or more sequences (exabeam-1.0). Exabeam evaluates the sequences in order: it waits one minute before it evaluates the next one, and an any-match sequence evaluates events for one minute. Its guide asks for a correlation window of more than the sum of the sequence windows (`threshold.within`, one minute for an any-match sequence) plus one minute for each sequence after the first: "more than nine minutes" for a 3-minute and a 5-minute sequence. A shorter window may never see every condition met. It is an advisory: the rule validates and deploys.

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

Make `correlation.within` more than the minutes the sequences need: 60 + 1 + 1 = 62 here, so `63m` or `2h`.
