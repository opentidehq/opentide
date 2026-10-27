# not_a_configuration_file

The file is not one opentide reads as configuration, or it has no configuration model to check it against.

Severity: warning. Reported by the configuration file check an editor runs (`configuration_file_issues`) for a file under `.opentide/configurations/` that no model covers, such as `resources.toml` or `lint.toml` (which `opentide lint` checks itself), and for a file under `.opentide/schemas/`, which holds generated artifacts.

## Example

```text
.opentide/configurations/deployement.toml   # misspelt: opentide reads deployment.toml
```

## How to fix

Rename a misspelt file to the name opentide reads. A file opentide does not read can be removed.
