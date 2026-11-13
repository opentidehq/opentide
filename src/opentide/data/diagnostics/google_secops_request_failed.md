# google_secops_request_failed

A Chronicle API request for one Google SecOps rule failed.

Severity: error. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0). Google answered an error other than the ones deploy handles itself, or stayed rate limited (`RESOURCE_EXHAUSTED` or HTTP 503) after three waits: `Retry-After` (at most 300 seconds), else the `RetryInfo` delay Google names, else 5, 15 and 60 seconds. The message carries Google's `error.status` and `error.message`. The other rules still deploy.

## Example

```text
google_secops_request_failed: INVALID_ARGUMENT: the rule text is too long
```

## How to fix

Read Google's status and message; deploy again once the cause is fixed.
