# exabeam_request_failed

An Exabeam call for one rule failed.

Severity: error. Reported by `opentide deploy` on an `exabeam` block (exabeam-1.0). A call answered an error other than the ones deploy handles itself: not `400` (`exabeam_request_rejected`), not a `404` deploy recovers from, and not a refusal that stops the tenant. The other rules still deploy.

## Example

```text
exabeam_request_failed: PUT /correlation-rules/v2/rules/016dbc1d-a727-43df-a143-9546dcc81a5a: HTTP 502: Bad Gateway
```

## How to fix

Deploy again later. If it keeps failing, check the tenant's status page and the message's details.
