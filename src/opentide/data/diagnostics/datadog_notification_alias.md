# datadog_notification_alias

A case's `notify` names an alias the tenant does not define.

Severity: error. Reported by `opentide deploy` on a `datadog` block (`platform::datadog::1.0`). Also reported by `opentide deploy --dry-run` and `validate query --live` for a tenant the run reaches. An entry that starts with `@` is a Datadog handle and is sent as written; any other entry is an alias, which `[tenants.setup.notifications]` in `platforms/datadog.toml` maps to a handle. A dry run with no tenant shows an alias as `<tenant:notifications.ALIAS>`.

## Example

```toml
# platforms/datadog.toml: no secops alias for notify: [secops]
[tenants.setup.notifications]
soc = "@slack-soc-alerts"
```

## How to fix

Add the alias to the tenant's `notifications`, or write the `@handle` itself.
