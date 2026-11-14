# google_secops_rule_execution_limited

Google reports that it limits or pauses a Google SecOps rule's runs.

Severity: warning. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0), from the rule deployment it reads before an update. `executionState` `LIMITED` means Google does not guarantee the rule's runs, usually because it is expensive or produces too many detections; `PAUSED` means Google does not run it at all. Deploy goes on: the text and run state are still updated.

## Example

```text
google_secops_rule_execution_limited: Google reports the rule's execution as PAUSED: it is not run at all
```

## How to fix

Open the rule in Google SecOps (Detection, Rules) to see why. Narrow `events` (filter on `metadata.event_type` or `metadata.log_type`), shorten the `match` window, or reduce the detections it produces, then deploy again.
