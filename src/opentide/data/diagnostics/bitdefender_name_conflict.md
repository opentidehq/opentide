# bitdefender_name_conflict

GravityZone refused a create because a rule with the same name exists in the company.

Severity: error. Reported by `opentide deploy` on a `bitdefender` tenant. GravityZone names are unique per company, and deploy never adopts a rule it did not create: it has no id for it in `.opentide/states/deployment/`. `opentide validate` reports two opentide rules with one GravityZone name as `bitdefender_name_duplicate`; this code is a rule created outside opentide, or by another workspace.

## Example

```yaml
name: Office application spawns encoded PowerShell   # a console rule has this name
configurations:
  bitdefender:
    status: PRODUCTION
```

## How to fix

Set a distinct `configurations.bitdefender.name`, or delete the other rule in the console. To take over a rule opentide created and lost track of, record its id in the rule's deployment state shard.
