# schema_validation

An object does not match the schema its `metadata.schema` names.

Severity: error. Reported by `opentide validate` (schema check).

## Example

```yaml
metadata:
  schema: rule::1.0
severity: 3          # must be one of the severity names
```

## How to fix

The message is the schema's own (a missing required field, a wrong type, an unknown key). The location points at the field, or at the mapping it belongs in when the field is missing. Compare the object with the template under `.opentide/templates/`, or let your editor validate it against the generated JSON schema (`opentide setup vscode`). A `metadata.schema` that names no registered revision, or another object type, is reported with this code as well.
