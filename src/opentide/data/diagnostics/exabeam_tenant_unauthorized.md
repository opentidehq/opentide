# exabeam_tenant_unauthorized

Exabeam refused the tenant's API key, so nothing more is sent to it.

Severity: error. Reported by `opentide deploy` on an `exabeam` block (exabeam-1.0). The token request was refused, or a call answered `401` after one new token, or `403`. Deploy stops the tenant. The key needs Correlation Rules at Read Write Delete; `validate query --live` and `opentide query` also need Search, Analyze and Export.

## Example

```text
exabeam_tenant_unauthorized: tenant exabeam-eu refused the API key: HTTP 401
```

## How to fix

Check the variables `client_id` and `client_secret` name, the tenant's `region` (or `api_url`), and the key's role in the Exabeam console (Settings, API Keys).
