# microsoft_defender_placeholder_limit

A Microsoft Defender alert title or description references more than three columns.

Severity: warning. Reported by `opentide validate` (its `schema` check) and `opentide lint` (its `queries` check) on a `microsoft_defender` block (microsoft-defender-1.0), at `alert.title` or `alert.description`, when the field references more than three distinct columns as `{{Column}}`. Microsoft's [custom detection docs](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules) (read 2026-11-26) say of a dynamic alert title and description: "You can reference up to three columns in each field." A column referenced twice counts once. What Defender does with a fourth is not documented, so this is an advisory: the rule validates and deploys, and `validate --strict` reports it without failing until a tenant check settles it.

## Example

```yaml
configurations:
  microsoft_defender:
    alert:
      title: "{{AccountName}} ran {{FileName}} on {{DeviceName}} from {{FolderPath}}"
```

## How to fix

Keep three columns in the field, and show the others as custom details (`alert.custom_details`), which the alert side panel lists.
