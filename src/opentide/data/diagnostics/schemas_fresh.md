# schemas_fresh

Every JSON schema this opentide version generates exists and matches what `opentide generate schemas` writes now.

Reported by `opentide doctor`. Warns when one is missing or its text differs from what the phase would write: the schemas are built from the workspace's objects (a rule's `detection_model` offers their names), its visibility, statuses and enabled platforms, so a changed object or configuration makes them stale, as does a schema another opentide version wrote. Line endings and a byte order mark are not compared. If the workspace does not open, only the presence of each schema is checked, and the message says so.

## Example

```text
! 1 schema(s) differ from what `generate schemas` writes now (objects or configuration changed, or another version wrote them): rule.1.0.schema.json · schemas_fresh
  → opentide generate schemas
```

## How to fix

Run `opentide generate schemas`.
