# google_secops_create_no_id

A Google SecOps create answered without a rule id.

Severity: error. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0). Google answered 2xx with a `name` that does not end in a rule id, or with a body that is not JSON. The `name` of the created rule must end in `rules/ru_<uuid>`, the id deploy records in `.opentide/states/deployment/`. Without it the rule may exist on the instance with no binding.

## Example

```text
google_secops_create_no_id: rules.create for password_spray answered name None, which does not end in a rule id
```

## How to fix

Find the rule in Google SecOps (Detection, Rules) by its name. Delete it, or record its `ru_` id under `platforms.google_secops.<tenant>` in the rule's `.opentide/states/deployment/<uuid>.json` and commit it.
