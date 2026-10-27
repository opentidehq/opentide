# promotion_target_unknown

`deployment.toml` `[promotion] promotion_target` is not the name of a `[[statuses]]` entry.

Severity: error. Reported by `opentide validate` (check `configuration`).

## Example

```toml
[promotion]
enabled = true
promotion_target = "LIVE"   # no [[statuses]] entry is named LIVE
```

## How to fix

Set `promotion_target` to a status name declared in the merged `deployment.toml`, or declare the status.
