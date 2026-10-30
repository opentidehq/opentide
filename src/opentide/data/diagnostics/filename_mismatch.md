# filename_mismatch

An object file's name is not the stem `lint.toml` `[filenames].style` asks for: `slugify(name)` by default.

Severity: warning. Reported by `opentide lint` (filenames check).

## Example

```text
objects/threats/Simulated Actor.yaml   # name: Simulated Actor → simulated-actor.yaml
```

With `style = "name"` the stem is the name, less the characters a file name cannot hold (`< > : " / \ | ? *`, control characters, and spaces or dots at either end):

```text
objects/threats/actor.yaml   # name: Simulated Actor → Simulated Actor.yaml
```

## How to fix

Run `opentide lint --fix`, which renames the file. When another file already has the expected name (compared without regard to case), the object gets the first eight characters of its UUID as a suffix.

If the catalogue keeps another convention, set `style` in `.opentide/configurations/lint.toml`: `"name"` for the object's name as the file name, `"none"` to stop comparing the stem with the name. `pattern` checks the stem against a regular expression (`opentide explain filename_pattern`).
