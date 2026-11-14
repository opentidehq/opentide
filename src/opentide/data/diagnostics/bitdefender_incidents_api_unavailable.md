# bitdefender_incidents_api_unavailable

The tenant has no Incidents API, so it cannot take custom rules.

Severity: error. Reported by `opentide deploy` on a `bitdefender` block (bitdefender-1.0). GravityZone answered `-32601` (method not found). On-premises GravityZone has no Incidents API.

## Example

```toml
url = "https://gravityzone.example.internal/api"   # on-premises
```

## How to fix

Use a GravityZone cloud or partner console URL, ending in `/api`.
