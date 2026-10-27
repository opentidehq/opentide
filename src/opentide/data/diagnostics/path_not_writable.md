# path_not_writable

`opentide new` could not create the folder or the file it scaffolds, because the operating system refused the write: a read-only checkout, a folder another user owns, or a full disk.

Exit 1, as `failure.code`. The message names the file and the system's reason (`Permission denied`, `Read-only file system`).

## Example

```text
error: Could not write objects/threats/credential-dumping.yaml: Permission denied
```

## How to fix

Make the folder writable (`ls -ld objects/threats` shows its owner and mode), run `opentide new` from a checkout you can write, or pass `--path` to write the file somewhere you can and move it later.
