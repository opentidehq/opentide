# microsoft_defender_custom_details

A Microsoft Defender block's `alert.custom_details` is not a mapping of non-blank names to result columns.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `microsoft_defender` block (microsoft-defender-1.0). Each key is the custom detail's name, and each value the result column it shows. The finding is on `alert.custom_details`, or on the detail whose value is not a string.

## Example

```yaml
configurations:
  microsoft_defender:
    alert:
      custom_details: [ProcessCommandLine]
```

## How to fix

Write a mapping: `custom_details: {CommandLine: ProcessCommandLine}`.
