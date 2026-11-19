# google_secops_tenant_unreachable

A Google SecOps instance did not answer, so no rule was deployed to it.

Severity: error. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0). A request to the instance's endpoint, or to Google's token endpoint, failed in transit (DNS, TLS, a refused or reset connection, a timeout). The tenant stops; the others go on.

## Example

```text
google_secops_tenant_unreachable: google_secops tenant 'eu' at https://eu-chronicle.googleapis.com sent no answer within 30s
```

## How to fix

Check the tenant's `location` (or `endpoint`), the network and proxy between the runner and Google, and `ssl`; then deploy again.
