# elastic_dataset_not_declared

The index pattern or data view is not one the workspace declares in visibility.toml.

Severity: warning. Reported by the analysis engine on an Elastic rule (`elastic`): its `index`, `data_view_id`, a threat match's `index`, or an ES|QL `FROM`. `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it; `opentide validate` does not fail on it. It is opt-in per kind: only a workspace whose `visibility.toml` names at least one Elastic index pattern (or data view) gets it. A declared pattern covers the patterns inside it: `logs-*` covers `logs-azure.*`.

## Example

```toml
[[logsources]]
name = "Endpoint telemetry"
description = "Elastic Defend endpoint data."
system = "elastic"
indices = ["logs-endpoint.events.*"]
```

```yaml
configurations:
  elastic:
    index:
      - winlogbeat-*   # not declared for elastic
```

## How to fix

Correct the pattern, or add it to the `indices` (or the data view to `data_views`) of the log source that fills it in `visibility.toml`. The editor applies the change as you type it; the CLI reads the file on its next run. See [The datasets a log source fills](../usage/configuration.md#the-datasets-a-log-source-fills).
