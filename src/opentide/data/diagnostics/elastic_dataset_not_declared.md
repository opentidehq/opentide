# elastic_dataset_not_declared

The index pattern is not one the workspace declares in visibility.toml.

Severity: warning. Reported by the analysis engine on an Elastic rule (`elastic`): its `index`, a threat match's `index`, or an ES|QL `FROM`. `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it, with the query's findings; `opentide validate` does not fail on it. It is opt-in: only a workspace whose `visibility.toml` has at least one `elastic` log source gets it, for an index pattern no log source names, whether or not the engine knows it otherwise. An Elastic log source's `name` is its index pattern or data stream; data views are not declared. A declared pattern covers the patterns inside it: `logs-*` covers `logs-azure.*`.

## Example

```toml
[[logsources]]
name = "logs-endpoint.events.*"
description = "Elastic Defend endpoint data."
system = "elastic"
```

```yaml
configurations:
  elastic:
    index:
      - winlogbeat-*   # not declared for elastic
```

## How to fix

Correct the pattern, or declare it: add an `elastic` log source whose `name` is the index pattern in `visibility.toml`. The editor applies the change as you type it; the CLI reads the file on its next run. See [The datasets a log source fills](../usage/configuration.md#the-datasets-a-log-source-fills).

```toml
[[logsources]]
name = "winlogbeat-*"
description = "Windows event logs shipped by Winlogbeat."
system = "elastic"
```
