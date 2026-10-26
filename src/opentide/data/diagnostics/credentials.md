# credentials

Per configured tenant, whether every `$VARIABLE` its setup names is set.

Reported by `opentide doctor`. Warns when a variable is unset or empty, with `subject` as `platform/tenant`; skipped when the platform has no tenant. It never prints a value.

## Example

```text
! sentinel/prod: 1 of 2 variables unset: AZURE_CLIENT_SECRET · credentials
  → set AZURE_CLIENT_SECRET in the environment (or a .env file you load)
```

## How to fix

Set the variables it names in the environment the deploy runs in (a CI secret, or a `.env` file you load). Never write the value into the TOML.
