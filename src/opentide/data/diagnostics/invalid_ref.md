# invalid_ref

A reference names an object that does not exist.

Severity: error. Reported by `opentide validate` (schema check).

## Example

```yaml
detection_model: 00000000-0000-4000-8002-DEADBEEF0000   # no such objective
```

## How to fix

Point the field at an object that exists: `detection_model` takes an objective or signal UUID (`opentide info objectives`), `objective.threats` and `threat.chaining[].vector` take threat UUIDs (`opentide info threats`). When the value is close to the name of an object, `help` names that object's UUID. A reference field is also a vocabulary field, but a dangling value is reported once, under this code.
