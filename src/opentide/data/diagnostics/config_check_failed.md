# config_check_failed

opentide could not check this configuration file in the editor; the message says why. Its other findings are missing.

Severity: warning. Reported by the language server (`opentide lsp start`) on the first line of a file under `.opentide/configurations/` when the configuration check itself fails, for example because opentide raised an error while reading the parent instance's file. Nothing about the file is reported until the check runs again, so the file may still have problems `opentide validate` finds.

## Example

```text
opentide could not check this file: ImportError: cannot import name 'configuration_buffer_issues'
```

## How to fix

Run `opentide validate` in the workspace to see the file's findings and any error behind this one. If the message names an import or version error, the editor runs a different opentide than the one you installed: point the editor at it, or reinstall with `pip install --force-reinstall opentide`. Then edit the file or restart the language server to check it again.
