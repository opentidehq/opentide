# google_secops_rule_conflict

A Google SecOps rule changed between deploy's read and its update.

Severity: error. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0). The text update carried the `etag` of the rule deploy had just read, and Google refused it (HTTP 409, `ABORTED`): someone or something changed the rule in between. Nothing was written, and deploy does not retry in the same run.

## Example

```text
google_secops_rule_conflict: rule ru_cfc80c6b-f918-42ed-8d5c-9518c13586c1 changed between its read and the update (etag mismatch)
```

## How to fix

Deploy again. When it keeps happening, find what else edits the rule in Google SecOps.
