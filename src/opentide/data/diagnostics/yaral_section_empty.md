# yaral_section_empty

A YARA-L section key is present with no text.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `configurations.google_secops` block (yara-l-1.0). The key loaded as YAML `null` or blank text, or as a YAML list or mapping instead of text. A plain YAML scalar that starts with `#` is a YAML comment, so `condition: #fail > 3` loads as null.

## Example

```yaml
configurations:
  google_secops:
    condition: #e > 5
```

## How to fix

Write each section as a block scalar (`|`), which YAML keeps verbatim:

```yaml
configurations:
  google_secops:
    condition: |
      #e > 5
```
