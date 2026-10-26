# yaml_parse

An object file is not valid YAML, or not one mapping, so it could not be loaded.

Severity: error. Reported by `opentide validate` (schema and id-uniqueness checks) and `opentide lint`. `opentide deploy` stops on a rule file whose YAML is a list or a single value, with exit 1 and `failure.code` `yaml_parse`.

## Example

```yaml
metadata:
  tlp: [clear        # the flow list is never closed
  author: Tutorial Author
```

## How to fix

Open the file at the line and column the diagnostic names. The note says what the parser was reading when it gave up, and where that started: an unclosed `[` or `{`, a missing quote, a tab used for indentation, or a key indented under a scalar. A key repeated in the same mapping is reported here too. A file whose top level is a list (`- name: …`) or a single value is reported as "expected a mapping at the top of the file": an object file is one mapping of keys such as `name`, `metadata` and `description`. The file is not indexed until it parses, so no other check can see it.
