# exabeam_context_table_trigger

A sequence whose query looks a value up in a context table has a threshold.

Severity: error. Reported by `opentide validate` on an `exabeam` block (exabeam-1.0). Exabeam requires "Trigger on first match" for a sequence with a context table lookup (`user IN "Privileged Accounts"`), so the sequence takes no `threshold`.

## Example

```yaml
sequences:
  - query: activity_type:"app-login" AND user IN "Privileged Accounts"
    threshold:
      function: count
      operator: more_than
      value: 5
      within: 1h
```

## How to fix

Remove the `threshold`, or move the lookup to a sequence of its own that triggers on any match and correlate the two.
