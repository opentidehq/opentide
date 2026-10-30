# filename_pattern

An object file's name does not match the regular expression `lint.toml` sets for it.

Severity: warning, or the severity `[filenames]` sets. Reported by `opentide lint` (filenames check), only when `[filenames].pattern` is set.

## Example

```toml
# .opentide/configurations/lint.toml
[filenames]
style = "name"
pattern = '^\[(SEN|XDR)\]\[[^\]]+\].+\[[^\]]+\]$'
```

```text
objects/rules/Some rule.yaml   # the stem is not [PLATFORM][GROUP]name[TENANT]
```

## How to fix

The pattern is matched against the whole file name without its extension (`re.fullmatch`), whatever `style` is. `lint --fix` cannot rename the file, because no name derives from a pattern: rename it so the stem matches, or change `pattern` in `.opentide/configurations/lint.toml` if the convention changed.

`pattern` applies together with `style`. When `style` asks for a stem and `lint --fix` renames the file to it, the pattern is checked against the new name. With `style = "name"` the stem is the object's `name`, so a stem that fails the pattern after `--fix` means the `name` itself does not fit it: change the name. With `style = "none"` only the pattern is checked.
