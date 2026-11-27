# datadog_site

A tenant's `site` is not a Datadog site, and no `api_url` is set.

Severity: error. Reported by `opentide deploy` on a `datadog` block (`platform::datadog::1.0`). The sites are `datadoghq.com`, `us3.datadoghq.com`, `us5.datadoghq.com`, `datadoghq.eu`, `ap1.datadoghq.com`, `ap2.datadoghq.com`, `uk1.datadoghq.com`, `ddog-gov.com` and `us2.ddog-gov.com`; calls go to `https://api.<site>`.

## Example

```toml
[tenants.setup]
site = "app.datadoghq.eu"
```

## How to fix

Write the site, not the web address (`datadoghq.eu`), or set `api_url` for a new site or a proxy.
