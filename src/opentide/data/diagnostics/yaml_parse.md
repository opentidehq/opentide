# yaml_parse

An object file is not valid YAML, so it could not be loaded.

Severity: error. Reported by `opentide validate` (schema and id-uniqueness checks) and `opentide lint`.

## Example

```yaml
metadata:
  tlp: [clear        # the flow list is never closed
  author: Tutorial Author
```

## How to fix

Open the file at the line and column the diagnostic names. The note says what the parser was reading when it gave up, and where that started: an unclosed `[` or `{`, a missing quote, a tab used for indentation, or a key indented under a scalar. A key repeated in the same mapping is reported here too. The file is not indexed until it parses, so no other check can see it.
