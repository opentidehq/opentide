# exabeam_outcome_silent

An Exabeam block has `outcome: none` and no `email`, so nobody is told when it triggers.

Severity: warning. Reported by `opentide validate` and `opentide lint` (its `queries` check) on an `exabeam` block (exabeam-1.0). The rule only writes a `rule-trigger` event. It is an advisory: the rule validates and deploys.

## Example

```yaml
configurations:
  exabeam:
    outcome: none
```

## How to fix

Use `outcome: alert` or `case`, add an `email`, or keep it if the trigger events are all you want.
