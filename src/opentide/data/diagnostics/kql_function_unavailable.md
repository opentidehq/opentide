# kql_function_unavailable

A KQL query calls a function that exists in another product's dialect, not in this one: a Microsoft Defender advanced hunting function in a Microsoft Sentinel query.

Severity: warning. Reported by the analysis engine in a KQL query under the Sentinel dialect (a `sentinel` block, or a Sentinel hunt), at the function's name: `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it; `opentide validate` does not fail on it. `lint --strict` fails on it, as on every warning; `kql_function_unavailable = "info"` under `[queries.codes]` in `lint.toml` keeps it reported without failing. The functions are advanced hunting's own, which Microsoft documents for advanced hunting in the Microsoft Defender portal: [`FileProfile()`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-fileprofile-function), [`DeviceFromIP()`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefromip-function) and [`SeenBy()`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-seenby-function), each called with `invoke`, and [`AssignedIPAddresses()`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-assignedipaddresses-function). A Log Analytics workspace, where Sentinel's analytics rules run, does not have them, so a rule that calls one fails to run. It is a warning, not an error, because a workspace can save a function of its own under the same name: declare it as a log source in `visibility.toml`, as any workspace function is declared, and the call is not reported. A function the query defines with `let` is not reported either.

## Example

```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| project SHA1
| invoke FileProfile()
```

## How to fix

Run the query in Microsoft Defender: move it to a `microsoft_defender` block. In Sentinel, read the same data from the workspace's own tables instead, or save a workspace function under that name and declare it as a log source in `visibility.toml`.
