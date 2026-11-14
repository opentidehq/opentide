# yaral_section_missing

A YARA-L rule has no `events` or no `condition` section.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `configurations.google_secops` block (yara-l-1.0). A rule needs both: `events` names what to match, `condition` when it fires. The finding is on the missing key.

## Example

```yaml
configurations:
  google_secops:
    events: |
      $e.metadata.event_type = "NETWORK_DNS"
```

## How to fix

Add the missing key, as a block scalar:

```yaml
configurations:
  google_secops:
    condition: |
      $e
```
