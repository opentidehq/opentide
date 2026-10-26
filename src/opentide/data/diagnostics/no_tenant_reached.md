# no_tenant_reached

`validate query --live` sent no query, because no configured tenant takes the rules.

Exit 2, as `failure.code`.

## Example

```text
opentide validate query --live --platform sentinel
```

## How to fix

Add a tenant for the platform in `.opentide/configurations/platforms/<platform>.toml`, or pass the `--strategy` the tenants deploy.
