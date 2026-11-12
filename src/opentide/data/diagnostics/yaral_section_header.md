# yaral_section_header

A YARA-L section text holds a section label, a `rule` header or a rule's braces.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `configurations.google_secops` block (yara-l-1.0). Each section is its own key, and deploy writes the `rule <name> {` header, the `meta` section and the labels itself. A label or a header inside a comment or a string does not count.

## Example

```yaml
configurations:
  google_secops:
    events: |
      rule office_powershell {
        events:
          $e.metadata.event_type = "PROCESS_LAUNCH"
        condition:
          $e
      }
```

## How to fix

Move each section's lines under its own key and drop the header, `meta` and braces:

```yaml
configurations:
  google_secops:
    events: |
      $e.metadata.event_type = "PROCESS_LAUNCH"
    condition: |
      $e
```
