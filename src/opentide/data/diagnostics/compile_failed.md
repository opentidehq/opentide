# compile_failed

The platform's compiler rejected the rule for a reason opentide cannot name more precisely.

Severity: error. Reported by `opentide deploy --dry-run` (and a real deploy) for one rule on one platform; the dry run lists the rule as failed and exits 1. The message quotes what the compiler said.

## Example

```text
error[compile_failed]: Sentinel cannot compile this rule: …
  --> objects/rules/lsass-access.yaml
```

## How to fix

Read the quoted reason and fix the rule's platform block. Run `opentide validate --file <path>` first; if the rule validates and still fails here, add `--debug` and open an issue.
