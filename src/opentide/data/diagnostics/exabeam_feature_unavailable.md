# exabeam_feature_unavailable

The Exabeam tenant's subscription does not include the feature, so no rule deploys to it.

Severity: error. Reported by `opentide deploy` on an `exabeam` block (exabeam-1.0). Exabeam answered `409` ("Feature is not enabled for subscription"). Deploy stops the tenant.

## Example

```text
exabeam_feature_unavailable: tenant exabeam-eu answered POST /correlation-rules/v2/rules with HTTP 409: Feature is not enabled for subscription
```

## How to fix

Ask Exabeam to enable correlation rules (Threat Detection Management) for the tenant, or remove the tenant from `exabeam.toml`.
