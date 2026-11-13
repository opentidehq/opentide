# bitdefender_action_scope

An automatic action is not allowed for the rule's kind or target.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). `kill_process` is for Basic rules only. `sandbox`, `kill_process` and `quarantine` need a `process` or `file` target or a `*.CreatedBy.*` criterion; a YARA rule takes `sandbox` and `quarantine`.

## Example

```yaml
configurations:
  bitdefender:
    actions:
      kill_process: true
    yara:
      signature: |
        rule A { condition: true }
```

## How to fix

Remove the action, or use one the kind and target allow (`isolate`, `collect_investigation_package`, `antimalware_scan`, `risk_scan` are allowed everywhere).
