# google_secops_run_frequency_not_allowed

A Google SecOps block's `run_frequency` is not one Google allows for the rule.

Severity: error. Reported by `opentide deploy` before any write, and by `opentide validate query --platform google_secops --live` (google-secops-1.0). `verifyRuleText` answers the frequencies the rule can run at (`allowedRunFrequencies`): `LIVE` is for single-event rules, `LIVE_CUSTOMIZABLE` for multi-event windows under an hour, `HOURLY_CUSTOMIZABLE` up to two days, `DAILY` beyond.

## Example

```text
google_secops_run_frequency_not_allowed: run_frequency LIVE is not one Google allows for this rule (LIVE_CUSTOMIZABLE, HOURLY_CUSTOMIZABLE, DAILY); nothing was written
```

## How to fix

Set `run_frequency` to one of the frequencies the message lists, or remove it: deploy then sends no `runFrequency`, and Google keeps the rule's frequency, or gives a new rule its default.
