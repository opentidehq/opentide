# exabeam_rule_auto_disabled

Exabeam has stopped the rule on its own.

Severity: warning. Reported by `opentide deploy` on an `exabeam` block (exabeam-1.0). The rule a `PUT` returned has `autoDisabled: true`. Exabeam stops a rule that matches more than 500 times or triggers more than 50 times in five minutes, or whose query or context table is broken.

## Example

```text
exabeam_rule_auto_disabled: Exabeam stopped rule 016dbc1d-a727-43df-a143-9546dcc81a5a (autoDisabled)
```

## How to fix

Narrow the query or raise the threshold, check the context tables it reads, then re-enable the rule in the console.
