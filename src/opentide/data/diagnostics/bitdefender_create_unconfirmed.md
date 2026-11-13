# bitdefender_create_unconfirmed

A GravityZone create got no answer, and its retry found the name already taken.

Severity: error. Reported by `opentide deploy` on a `bitdefender` tenant. The first `createCustomRule` got no answer (a timeout, a reset or a cut-off response), so deploy sent it once more; the retry got no answer either, or GravityZone refused it because a rule of that name exists. The first create may have succeeded, but its rule id never reached opentide, so nothing was recorded in `.opentide/states/deployment/`. Deploy never lists rules to find the id.

## Example

```text
bitdefender_create_unconfirmed: the first create of 'Office application spawns encoded PowerShell'
got no answer and the retry found the name taken
```

## How to fix

Find the rule by its name in the GravityZone console (Incidents, Custom rules). Delete it and deploy again, or record its 24-hex id under `platforms.bitdefender.<tenant>` in the rule's `.opentide/states/deployment/<uuid>.json` and commit it.
