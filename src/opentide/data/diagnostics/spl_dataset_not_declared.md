# spl_dataset_not_declared

The index, sourcetype or macro is not one the workspace declares in visibility.toml.

Severity: warning. Reported by the analysis engine on an SPL search (`splunk`): `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it; `opentide validate` does not fail on it. It is opt-in per kind: only a workspace whose `visibility.toml` names at least one Splunk index (or sourcetype, or macro) gets it for an index (or sourcetype, or macro). Names match regardless of case, and `*` matches any run of characters.

## Example

```toml
[[logsources]]
name = "Windows security events"
description = "Security event log of the domain controllers."
system = "splunk"
indexes = ["wineventlog"]
```

```text
index=winevents EventCode=4688   # winevents is not declared
```

## How to fix

Correct the name, or add it to the `indexes`, `sourcetypes` or `macros` of the log source that fills it in `visibility.toml`, then run `opentide generate schemas` so the committed `datasets.json` follows. See [The datasets a log source fills](../usage/configuration.md#the-datasets-a-log-source-fills).
