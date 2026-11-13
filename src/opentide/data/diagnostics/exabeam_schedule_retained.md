# exabeam_schedule_retained

The Exabeam rule keeps a schedule the block no longer sets.

Severity: warning. Reported by `opentide deploy` on an `exabeam` block (exabeam-1.0). The rule a `PUT` returned still has a `scheduleConfig`. Exabeam does not document whether a `PUT` without one clears it, so the rule may still run only at the old times.

## Example

```text
exabeam_schedule_retained: Exabeam rule 016dbc1d-a727-43df-a143-9546dcc81a5a keeps a schedule the block no longer sets; clear it in the console
```

## How to fix

Clear the schedule in the Exabeam console, or set `schedule` in the block again.
