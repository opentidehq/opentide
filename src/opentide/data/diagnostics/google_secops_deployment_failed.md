# google_secops_deployment_failed

A Google SecOps rule exists, but its run state could not be set.

Severity: error. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0). The rule text was created or updated and its id is recorded, but the update of its deployment (`enabled`, `alerting`, `runFrequency`, `archived`) failed. The binding is kept: the next deploy repairs the run state.

## Example

```text
google_secops_deployment_failed: rule ru_cfc80c6b-f918-42ed-8d5c-9518c13586c1 is bound, but its run state could not be set
```

## How to fix

Read Google's error in the message (a permission such as `chronicle.ruleDeployments.update`, a run frequency) and deploy again.
