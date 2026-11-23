# file_not_found

A `--file` path names a file that does not exist, so it was not validated.

Severity: error. Reported by `opentide validate`, with the path in `context.targets`. It fails the `uuid-format`, `schema` and `queries` checks, as `scope_no_match` does; `scope_no_match` stays for a path that exists but matches no object.

## Example

```text
opentide validate --file objects/rules/does-not-exist.yaml
```

## How to fix

Fix the path: it is read relative to the working directory and to the workspace root, and whether its case matters depends on the filesystem. `--file` takes a path or a file name, not a glob: a quoted pattern such as `'objects/rules/*.yaml'` is reported here too, so let the shell expand it. Run `opentide validate` without `--file` to check every object.
