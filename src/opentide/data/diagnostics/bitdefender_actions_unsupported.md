# bitdefender_actions_unsupported

The block sets `actions`, and the tenant's subscription has no automatic actions.

Severity: warning. Reported by `opentide deploy` on a `bitdefender` block (bitdefender-1.0). With `automatic_actions = false` in the tenant setup, deploy omits `automaticActions` and the rule deploys without them.

## Example

```yaml
configurations:
  bitdefender:
    actions:
      isolate: true   # tenant: automatic_actions = false
```

## How to fix

Remove the block's `actions`, or set `automatic_actions = true` once the subscription includes them.
