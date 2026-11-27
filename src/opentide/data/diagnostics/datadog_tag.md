# datadog_tag

A tag Datadog would refuse or rewrite.

Severity: error. Reported by `opentide validate` on a `datadog` block (`platform::datadog::1.0`). Also reported by `opentide deploy` for a tenant's `tags`. A tag starts with a lower-case letter, holds only `a-z`, `0-9`, `_`, `-`, `:`, `.` and `/`, and is at most 200 characters. Datadog lowers upper case and replaces other characters, so the rule it holds would differ from the one opentide compiled.

## Example

```yaml
configurations:
  datadog:
    tags: ["Team:Identity"]
```

## How to fix

Write the tag in lower case with the allowed characters: `team:identity`.
