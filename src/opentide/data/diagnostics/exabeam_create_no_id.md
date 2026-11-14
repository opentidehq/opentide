# exabeam_create_no_id

Exabeam answered a create without a rule UUID.

Severity: error. Reported by `opentide deploy` on an `exabeam` block (exabeam-1.0). The create returned `201`, but its `id` is not a UUID, so nothing was recorded in `.opentide/states/deployment/`. The rule may exist on the tenant with no binding.

## Example

```text
exabeam_create_no_id: the create of 'Password spraying from outside the network' answered no rule UUID (id None)
```

## How to fix

Find the rule by its name in the Exabeam console. Delete it and deploy again, or record its id under `platforms.exabeam.<tenant>` and commit it.
