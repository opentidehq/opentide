# yaral_match_shape

A YARA-L `match` is not a `YaraLMatch` object.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `configurations.google_secops` block (yara-l-1.0). `match` takes `group_by` (a non-empty list of distinct `$placeholders`), `window`, `type` (`hop`, `tumbling` or `sliding`), and, for `sliding` only, `pivot` (an `$event`) and `direction` (`before` or `after`). The finding is on `match` or on the field at fault.

## Example

```yaml
configurations:
  google_secops:
    match:
      group_by: [$user]
      window: 5m
      type: sliding
```

## How to fix

Add the event the sliding window is anchored on and its direction, or use a hop window:

```yaml
configurations:
  google_secops:
    match:
      group_by: [$user]
      window: 5m
      type: sliding
      pivot: $login
      direction: after
```
