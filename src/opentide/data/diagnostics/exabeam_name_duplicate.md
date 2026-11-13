# exabeam_name_duplicate

Two enabled Exabeam blocks resolve to the same Exabeam rule name.

Severity: error. Reported by `opentide validate` on an `exabeam` block (exabeam-1.0). The Exabeam rule name is the block's `name`, else the rule's `name`, compared case-insensitively. Exabeam's import refuses a rule whose name exists and Search links rules by name, so the second deploy would fail with `exabeam_name_conflict`.

## Example

```yaml
# rule-a.yaml and rule-b.yaml, both:
name: Password spraying from outside the network
configurations:
  exabeam:
    enabled: true
```

## How to fix

Give one of the blocks its own `configurations.exabeam.name`, or rename one of the rules.
