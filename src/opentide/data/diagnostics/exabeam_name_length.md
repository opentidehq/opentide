# exabeam_name_length

The Exabeam rule name is longer than 128 characters.

Severity: error. Reported by `opentide validate` and `opentide deploy` on an `exabeam` block (exabeam-1.0). The Exabeam rule name is the block's `name`, else the rule's `name`; Exabeam takes at most 128 characters, and deploy never sends a longer one.

## Example

```yaml
name: A very long rule name that keeps going well past the one hundred and twenty-eight characters an Exabeam rule name may hold, and more
configurations:
  exabeam:
    enabled: true
```

## How to fix

Set a shorter `configurations.exabeam.name`, or shorten the rule's `name`.
