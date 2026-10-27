# compile_invalid_rule

The rule does not load as a detection rule the platform can compile.

Severity: error. Reported by `opentide deploy --dry-run` (and a real deploy) for one rule on one platform; the dry run lists the rule as failed and exits 1. The message is the data model's own error.

## Example

```text
error[compile_invalid_rule]: …
  ╰─▶ objects/rules/lsass-access.yaml
```

## How to fix

Run `opentide validate --file <path>` on the rule: it reports the same problem as a code frame at the line, with a fix when one is safe.
