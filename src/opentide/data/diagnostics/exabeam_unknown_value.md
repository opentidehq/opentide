# exabeam_unknown_value

An Exabeam `activity_type`, `subject` or `outcome` value is not one the Common Information Model lists.

Severity: warning. Reported by the analysis engine in an Exabeam Query Language query (`exabeam`, language-exabeam 1.1), at the value: `opentide lint` (its `queries` check), `opentide validate query` and an editor running `opentide lsp start` show it, and `opentide validate` does not fail on it. A tenant's parsers may emit values the CIM lacks, so it is never an error, but a value no event carries makes the filter match nothing. Values compare without regard to case. Wildcards, `WLD`/`RGX` calls, values between slashes, `null`, an empty value, an unquoted number or IP address, a `@field` and an `AS` name defined earlier are not checked. Engines before language-server 0.16.1 do not report it.

## Example

```text
activity_type:"network-connection" AND process_name:"powershell.exe"
```

## How to fix

Use the CIM's value, which the message suggests when one is close (`process_create` → `process-create`) and the editor completes: here `network-session` or `network-traffic`. An `activity_type` is `<subject>-<activity>`. If the tenant really emits the value, confirm it with `opentide query --platform exabeam` and keep it. Then run `opentide lint --check queries` again.

```text
activity_type:"network-session" AND process_name:"powershell.exe"
```
