# datadog_query_name

A query name is not `[a-z][a-z0-9_]*`, is a duplicate, or is set on a `new_value` query.

Severity: error. Reported by `opentide validate` on a `datadog` block (`platform::datadog::1.0`). Conditions call queries by name. An unnamed query is called `a`, `b`, … by its position, so a query named `a` after an unnamed first query clashes with it. A `new_value` query takes no name: Datadog's own provider calls the two not compatible.

## Example

```yaml
configurations:
  datadog:
    queries:
      - name: Failed-Logins
        query: source:okta @evt.outcome:FAILURE
```

## How to fix

Use lower-case letters, digits and underscores, starting with a letter (`failed_logins`), and give each query its own name.
