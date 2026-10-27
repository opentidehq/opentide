# nested_object_file

A YAML file sits in a subfolder of an object folder, so it is not an object and no command reads it.

Severity: warning. Reported by `opentide validate` and `opentide lint`, and named in the `warnings` of `share`, `generate docs` and `export`. `validate --strict` and `lint --strict` fail on it. Only files placed directly in `objects/rules/`, `objects/threats/` and `objects/objectives/` (or the configured folders) are objects: a file one folder down is not indexed, validated, shared, documented or deployed ([#584](https://github.com/opentidehq/opentide/issues/584)).

## Example

```text
objects/rules/team-a/rule.yaml is in a subfolder of objects/rules and is not an object instance
```

## How to fix

Move the file up into its object folder (`git mv objects/rules/team-a/rule.yaml objects/rules/`), or delete it if it is a stale copy.
