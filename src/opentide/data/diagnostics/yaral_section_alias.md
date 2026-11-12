# yaral_section_alias

A YARA-L section key is a YAML alias instead of its own text.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `configurations.google_secops` block (yara-l-1.0). What a block deploys must be readable in the block: an alias makes a change to the anchored text, under any other key, change the deployed rule too. The YAML loader cannot tell an alias from text written in place, so `opentide validate` reads the file's node graph.

## Example

```yaml
description: &shared |
  $e
configurations:
  google_secops:
    condition: *shared
```

## How to fix

Write the section text under its key with a block scalar (`|`).
