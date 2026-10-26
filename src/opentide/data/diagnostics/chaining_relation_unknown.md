# chaining_relation_unknown

A threat's chaining relation is not a known relation.

Severity: error. Reported by `opentide validate` (schema check).

## Example

```yaml
threat:
  chaining:
    - relation: succeds
      vector: 00000000-0000-4000-8001-000000000002
```

## How to fix

Use a relation from the `chaining_relations` vocabulary. `help` names the closest one.
