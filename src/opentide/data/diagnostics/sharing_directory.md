# sharing_directory

A `sharing/` configuration directory exists; sharing is configured in one `sharing.toml` file.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

## Example

```text
.opentide/configurations/sharing/misp.toml
```

## How to fix

Move the blocks into `.opentide/configurations/sharing.toml` and remove the directory.
