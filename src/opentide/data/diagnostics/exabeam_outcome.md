# exabeam_outcome

The block `outcome` is not `alert`, `case` or `none`.

Severity: error. Reported by `opentide validate` on an `exabeam` block (exabeam-1.0). `alert` sends an alert to Threat Center (the default), `case` creates a case, and `none` only writes a `rule-trigger` event. An email is the separate `email` table.

## Example

```yaml
configurations:
  exabeam:
    outcome: webhook
```

## How to fix

Use `alert`, `case` or `none`. Webhooks are set in the Exabeam console, not through the API.
