# bitdefender_target_unknown

A `targets` alias is not in the tenant's `endpoint_tags` or `companies` table.

Severity: error. Reported by `opentide deploy`, before any call for the rule on a `bitdefender` block (bitdefender-1.0). A rule file carries aliases, because GravityZone ids differ per tenant; each tenant maps them in `platforms/bitdefender.toml`.

## Example

```yaml
configurations:
  bitdefender:
    targets:
      endpoint_tags: [tier0-servers]   # the tenant has no tier0-servers
```

## How to fix

Add the alias to the tenant's `[tenants.setup.endpoint_tags]` (or `companies`) table, or change the block's `targets`.
