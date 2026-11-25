# microsoft_defender_rule_absent

A Microsoft Defender rule to disable is not on the tenant, so nothing was disabled or created.

Severity: warning. Reported by `opentide deploy` on a `microsoft_defender` tenant (microsoft-defender-1.0). A `DISABLEMENT` status sends `PATCH {base}/{uuid}` with `status: disabled`; Graph answered `404`, so the tenant has no rule with the rule's `metadata.uuid`. Deploy does not create a rule only to disable it. The rule is reported as skipped.

## Example

```text
microsoft_defender_rule_absent: rule 00000000-0000-4000-8003-0000000000d0 is not on tenant 'contoso': nothing to disable
```

## How to fix

Nothing to do if the rule was never deployed to that tenant. If it was, it was deleted in the portal or deployed under another uuid: check the rule's `metadata.uuid`.
