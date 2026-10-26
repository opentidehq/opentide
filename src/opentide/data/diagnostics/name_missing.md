# name_missing

An object has no `name`, so lint cannot derive its file name.

Severity: error. Reported by `opentide lint` (filenames check).

## Example

```yaml
name: ""
metadata:
  uuid: 00000000-0000-4000-8001-000000000001
```

## How to fix

Give the object a `name`. The file name is derived from it.
