# bitdefender_contains_no_wildcard

A `contains` criterion has neither `*` nor `?`, so GravityZone matches the value as written.

Severity: warning. Reported by `opentide validate` and `opentide lint` (its `queries` check) on a `bitdefender` block (bitdefender-1.0). It is an advisory: GravityZone's `contains` relation compares the whole value with `*` and `?` as wildcards, so a value without one is an exact match, and the author most likely meant a substring.

## Example

```yaml
configurations:
  bitdefender:
    detection:
      target: process
      criteria:
        - field: Process.CommandLine
          contains: -enc
```

## How to fix

Add the wildcards you mean (`contains: "*-enc*"`), or use `is` for an exact match.
