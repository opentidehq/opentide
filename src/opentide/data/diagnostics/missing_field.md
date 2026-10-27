# missing_field

A configuration file is missing a required key, once it is merged with the bundled file and the parent instance.

Severity: error. Reported by `opentide validate` (check `configuration`) for the files under `.opentide/configurations/`, and by `opentide validate --check sharing-config` and `opentide share` for a `sharing.toml` block. A file that only overrides some keys is not reported for the keys it inherits.

## Example

```toml
[[misp]]
name = "misp-prod"
# url, max_tlp and api_key are required
```

## How to fix

Add the key the message names. `context.file` names the file and `field_path` the table it belongs to.
