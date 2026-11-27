# exabeam_tenant_unreachable

An Exabeam tenant did not answer, so no rule deploys to it.

Severity: error. Reported by `opentide deploy` on an `exabeam` block (exabeam-1.0). A request other than a create got no answer (a timeout, a refused connection, a TLS failure), or the token could not be had. Deploy stops the tenant.

## Example

```text
exabeam_tenant_deployment_failed: code=exabeam_tenant_unreachable tenant=exabeam-eu error=exabeam tenant 'exabeam-eu' at https://api.eu.exabeam.cloud sent no complete answer within 30s
```

## How to fix

Check the network path to `https://api.<region>.exabeam.cloud`, the tenant's `region` or `api_url`, and the proxy settings, then deploy again.
