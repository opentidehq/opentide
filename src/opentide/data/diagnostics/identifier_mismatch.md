# identifier_mismatch

A platform file's `[platform] identifier` differs from its file name.

Severity: error. Reported for `platforms/<id>.toml` by the configuration file check an editor runs (`configuration_file_issues`).

## Example

```toml
# platforms/sentinel.toml
[platform]
identifier = "splunk"
```

## How to fix

Make `identifier` match the file name stem, or remove it: the file name is used when it is absent.
