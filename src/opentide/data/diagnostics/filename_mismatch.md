# filename_mismatch

An object file's name is not `slugify(name)`.

Severity: warning. Reported by `opentide lint` (filenames check).

## Example

```text
objects/threats/Simulated Actor.yaml   # name: Simulated Actor → simulated-actor.yaml
```

## How to fix

Run `opentide lint --fix`, which renames the file. When another file already has the expected name, the object gets the first eight characters of its UUID as a suffix.
