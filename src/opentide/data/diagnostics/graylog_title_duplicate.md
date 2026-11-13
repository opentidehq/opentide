# graylog_title_duplicate

Two enabled Graylog blocks resolve to one event definition title.

Severity: warning. Reported by `opentide validate` on a `graylog` block (graylog-1.0); never fails a rule. The title is the block's `name`, else the rule's `name`. Graylog allows two definitions with one title, and its alert list cannot tell them apart.

## Example

```yaml
# rule-a.yaml and rule-b.yaml, both:
name: Office application spawns PowerShell
configurations:
  graylog:
    enabled: true
```

## How to fix

Give one of the blocks its own `configurations.graylog.name`, or rename one of the rules.
