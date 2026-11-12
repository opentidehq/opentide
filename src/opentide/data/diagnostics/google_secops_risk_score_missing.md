# google_secops_risk_score_missing

A Google SecOps rule's `outcome` assigns no `$risk_score`.

Severity: warning (an advisory: the rule still validates and deploys). Reported by `opentide validate` and `opentide lint` (its `queries` check) on a `google_secops` block (google-secops-1.0). Without `$risk_score`, Google gives every detection of the rule the instance's default score, 40 for an alert and 15 otherwise unless the instance's settings change them, whatever it detects.

## Example

```yaml
configurations:
  google_secops:
    outcome: |
      $host = $e.principal.hostname
```

## How to fix

Add a `$risk_score` line to `outcome`, an integer from 0 to 100 (`$risk_score = 70`), or an aggregation in a rule with `match` (`$risk_score = max(70)`).
