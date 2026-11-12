# google_secops_tenant_unauthorized

A Google SecOps instance refused opentide's credentials.

Severity: error. Reported by `opentide deploy` and `opentide validate query --live` on a `google_secops` tenant (google-secops-1.0). The instance answered HTTP 401 or 403, or Google refused to issue a token: no rule on that tenant is deployed or checked.

## Example

```text
google_secops_tenant_unauthorized: tenant secops-eu refused the request (HTTP 403 PERMISSION_DENIED): Permission 'chronicle.rules.create' denied
```

## How to fix

Give the service account (or the Application Default Credentials principal) the permissions on the instance: `chronicle.rules.verifyRuleText`, `.create`, `.get`, `.update`, `.delete`, `chronicle.ruleDeployments.get`, `.update`, and `chronicle.events.udmSearch` for `opentide query`. Check `project`, `location` and `instance` in `platforms/google_secops.toml`.
