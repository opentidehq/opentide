# placeholder

A value still holds the stand-in `opentide new` wrote for a required field nobody chose yet.

Severity: warning. Reported by `opentide lint` (placeholders check).

## Example

```yaml
threat:
  mitre_attack:
    - T1548  # opentide:placeholder
  description: |  # opentide:placeholder
    ...
```

## How to fix

Replace the value with the real one, then delete the `# opentide:placeholder` comment on that line. The object validates with the stand-in, so only `lint` notices it; `lint --strict` fails until every marker is gone. A placeholder query (`...`) is not sent to the analysis engine either: `validate`'s and `validate query`'s queries checks skip it, and `lint`'s `queries` check leaves it to this one.
