# datadog_create_unconfirmed

A Datadog create got no answer, or a server error, so it may or may not have happened.

Severity: error. Reported by `opentide deploy` on a `datadog` block (`platform::datadog::1.0`). The create timed out, the connection was reset, or Datadog answered `5xx`. Datadog may have created the rule, but its id never reached opentide. Deploy never sends a create again.

## Example

```text
datadog_create_unconfirmed: the create of 'Okta brute force followed by a successful login' got HTTP 503, so Datadog may have created it with an id opentide does not know
```

## How to fix

Look for the rule by its name, or by the tag `opentide_uuid:<uuid>`, in Datadog. Delete it and deploy again, or record its id under `platforms.datadog.<tenant>` in `.opentide/states/deployment/<uuid>.json` and commit it. If there is none, deploy again.
