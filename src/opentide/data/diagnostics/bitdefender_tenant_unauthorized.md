# bitdefender_tenant_unauthorized

GravityZone refused the tenant's API key, so no rule deploys to it.

Severity: error. Reported by `opentide deploy` on a `bitdefender` block (bitdefender-1.0). A `-32001` answer, HTTP 401 or HTTP 403 stops the tenant. The key must be valid and have the Incidents API enabled.

## Example

```text
bitdefender_tenant_unauthorized: tenant gravityzone-eu refused the API key: API Key is not allowed to access the selected API: Incidents
```

## How to fix

Check the variable `api_key` names, and enable the Incidents API for the key in GravityZone (My Account, API keys). `key_type` must match the key: `personal` or `service`.
