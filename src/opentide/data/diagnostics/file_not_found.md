# file_not_found

A `--file` path names a file that does not exist, so it was not validated.

Severity: error. Reported by `opentide validate`, with the path in `context.targets`. It fails the `uuid-format`, `schema` and `queries` checks, as `scope_no_match` does; `scope_no_match` stays for a path that exists but matches no object.

## Example

```text
opentide validate --file objects/rules/does-not-exist.yaml
```

## How to fix

Fix the path: it is read relative to the workspace and to the working directory, and is case-sensitive. `opentide validate` without `--file` lists every object it finds.
