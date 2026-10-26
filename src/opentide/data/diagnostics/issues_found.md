# issues_found

The command ran and failed on what it found.

Exit 1, as `failure.code`. Set by `validate` (errors, or warnings under `--strict`), `lint --strict` (findings) and `info --strict` (load errors). The findings are in the same document, each with its own code.

## Example

```text
opentide validate
```

## How to fix

Fix the findings the command printed. Each one names its code: `opentide explain <code>` says how to fix it. Then run the command again.
