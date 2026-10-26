# workspace

Where the workspace is, and how it was found.

Reported by `opentide doctor`. Fails when neither `.opentide/` nor `objects/` is in the folder; warns when there is `objects/` without `.opentide/`.

## Example

```text
✓ Workspace ./ has .opentide/ (found from the current directory) · workspace
```

## How to fix

Run `opentide doctor` from inside your detection repository, or pass `--repo`. Run `opentide setup` to create `.opentide/` in a new or legacy repository.
