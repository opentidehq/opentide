# graylog_definition_immutable

Graylog refuses to change or delete an event definition outside the default scope.

Severity: error. Reported by `opentide deploy` on a `graylog` block (graylog-1.0). Graylog answered "Immutable entity cannot be modified" or "Non-deletable entity cannot be deleted": the definition's `_scope` is not `DEFAULT` (a content pack or Illuminate installed it). Deploy always sends `_scope: DEFAULT` and never changes a scope.

## Example

```text
graylog_definition_immutable: Immutable entity cannot be modified; deploy never changes a definition's scope
```

## How to fix

Point the rule's binding in `.opentide/states/deployment/<uuid>.json` at a definition opentide created, or remove it so deploy creates one.
