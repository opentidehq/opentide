# google_secops_tenant_unauthorized

A Google SecOps instance refused opentide's credentials.

Severity: error. Reported by `opentide deploy` and `opentide validate query --live` on a `google_secops` tenant (google-secops-1.0). The instance answered HTTP 401 or 403, or no access token could be obtained (Google refused the credentials, or its token endpoint did not answer): no rule on that tenant is deployed or checked. A token failure happens before the request is sent, so it is never an unanswered create. User credentials from Application Default Credentials send their quota project (`x-goog-user-project`); Google refuses them without one.

## Example

```text
google_secops_tenant_unauthorized: tenant secops-eu refused the request (HTTP 403 PERMISSION_DENIED): Permission 'chronicle.rules.create' denied
```

## How to fix

Give the service account (or the Application Default Credentials principal) the permissions on the instance: `chronicle.rules.verifyRuleText`, `.create`, `.get`, `.update`, `.delete`, `chronicle.ruleDeployments.get`, `.update`, and `chronicle.events.udmSearch` for `opentide query`. Check `project`, `location` and `instance` in `platforms/google_secops.toml`. With user Application Default Credentials, set a quota project: `gcloud auth application-default set-quota-project <project>`.
