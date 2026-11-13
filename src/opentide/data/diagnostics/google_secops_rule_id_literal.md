# google_secops_rule_id_literal

A Google SecOps rule matches a producer rule by a literal `ru_…` id.

Severity: warning (an advisory). Reported by `opentide validate` and `opentide lint` on a `google_secops` block (google-secops-1.0). A rule id differs on every instance and changes when the rule is recreated, so a composite rule that compares `detection.detection.rule_id` with a literal stops matching after a redeploy or on another tenant.

## Example

```yaml
configurations:
  google_secops:
    events: |
      $d.detection.detection.rule_id = "ru_cfc80c6b-f918-42ed-8d5c-9518c13586c1"
```

## How to fix

Match the producer by its name, which opentide derives the same way on every instance: `$d.detection.detection.rule_name = "password_spray_then_success"`.
