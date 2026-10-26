# path_exists

`opentide new` would write a file that already exists, and it never overwrites one.

Exit 1, as `failure.code`. Raised when `--path` names an existing file, or when a file appears at the chosen path while `new` runs.

## Example

```text
opentide new threat --name "Credential Dumping" --path objects/threats/credential-dumping.yaml
```

## How to fix

Pass another `--path`, or leave `--path` out: without it, `new` appends `-<uuid[:8]>` to the file name when the name is taken. To start over, delete or move the existing file first.
