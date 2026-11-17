# issues_found

The command ran and failed on what it found.

Exit 1, as `failure.code`. Set by `validate` (errors, or under `--strict` warnings, or a full run that found no detection objects), `lint --strict` (findings), `info --strict` (load errors) and `deploy` (a rule the platform refused). The findings are in the same document, each with its own code; a `deploy` lists every rule in `results` with its `status`, the platform's message in `error`, and the rules it never reached as `not_attempted`.

## Example

```text
opentide validate
```

## How to fix

Fix the findings the command printed. Each one names its code: `opentide explain <code>` says how to fix it. When `validate --strict` failed because it found no detection objects, it printed no finding: check the folder it names (run it inside the workspace or pass `--repo`), or add a first object with `opentide new rule`. After a failed `deploy`, fix the rule on the `✗ failed` line, or the tenant it names, then run the command again: the rules before it were deployed, and the ones marked `not attempted` were not sent.
