# config_parse

A configuration file could not be read as TOML.

Severity: error. Reported for `sharing.toml` by `opentide validate --check sharing-config` and `opentide share`, and for the platform files and `deployment.toml` under `.opentide/configurations/` by every command that reads them (`validate`, `info`, `deploy`, …), which then stops with exit 1 and `failure.code` `config_parse`.

## Example

```toml
[[tenants]
name = "prod"
```

## How to fix

Open the file at the line and column the diagnostic names and fix the TOML syntax there: an unclosed `[[` header, a missing quote, or a key written twice. Then run the command again.
