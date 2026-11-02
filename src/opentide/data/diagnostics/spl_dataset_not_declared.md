# spl_dataset_not_declared

The sourcetype is not one the workspace declares in visibility.toml.

Severity: warning. Reported by the analysis engine on an SPL search (`splunk`): `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it; `opentide validate` does not fail on it. It is opt-in: only a workspace whose `visibility.toml` has at least one `splunk` log source gets it, for a sourcetype no log source names, whether or not the engine knows it otherwise. A Splunk log source's `name` is its sourcetype; indexes and macros are not declared. Names match regardless of case, and `*` matches any run of characters.

## Example

```toml
[[logsources]]
name = "WinEventLog:Security"
description = "Security event log of the domain controllers."
system = "splunk"
```

```text
sourcetype=XmlWinEventLog:Security EventCode=4688   # not declared
```

## How to fix

Correct the sourcetype, or declare it: add a `splunk` log source whose `name` is the sourcetype (or a pattern that covers it) in `visibility.toml`. The editor applies the change as you type it; the CLI reads the file on its next run. See [The datasets a log source fills](../usage/configuration.md#the-datasets-a-log-source-fills).

```toml
[[logsources]]
name = "XmlWinEventLog:Security"
description = "Security event log, XML rendering."
system = "splunk"
```
