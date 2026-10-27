# platform_not_enabled

A rule has a block for a platform this workspace has not enabled, so it will not deploy there.

Severity: warning. Reported by `opentide validate` (schema check); does not fail `--strict`.

## Example

```yaml
configurations:
  splunk:               # splunk is disabled in this workspace
    enabled: true
```

## How to fix

Enable the platform with the command the message names (`opentide setup platforms --<platform>`) when this workspace should deploy there. Otherwise leave the block: it is still validated and travels with the rule.

When the platform file sets a misspelling of `enabled` (`enabeld = true`, `Enabled = true`), the platform reads as disabled and the message names the file and the key instead: rename the key to `enabled`.
