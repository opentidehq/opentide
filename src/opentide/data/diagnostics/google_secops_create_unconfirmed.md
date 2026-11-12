# google_secops_create_unconfirmed

A Google SecOps create got no answer, so the rule may exist without a binding.

Severity: error. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0). The `rules.create` request timed out or its connection was reset. Google may have created the rule, but its id never reached opentide, so nothing was recorded, and deploy does not send the create again: a second rule with the same name would follow.

## Example

```text
google_secops_create_unconfirmed: the create of rule password_spray got no answer (read timed out)
```

## How to fix

Find the rule in Google SecOps (Detection, Rules) by its name. Delete it and deploy again, or record its `ru_` id under `platforms.google_secops.<tenant>` in the rule's `.opentide/states/deployment/<uuid>.json` and commit it.
