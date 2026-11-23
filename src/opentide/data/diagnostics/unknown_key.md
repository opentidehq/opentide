# unknown_key

A configuration file has a key opentide does not read, usually a misspelling.

Severity: error. Reported by `opentide validate` (check `configuration`) for the files under `.opentide/configurations/`, by every command that reads the file, and by `opentide validate --check sharing-config` and `opentide share` for `sharing.toml`. The message names the file and the key, never its value.

## Example

```toml
# deployment.toml
[promotion]
enabeld = false        # the key is enabled
```

## How to fix

Remove the key or correct its spelling. The keys each configuration file accepts are in [Configuration](../usage/configuration.md); `opentide setup platforms` writes a template that shows them, and an editor on `opentide lsp start` offers each file's keys as you type.
