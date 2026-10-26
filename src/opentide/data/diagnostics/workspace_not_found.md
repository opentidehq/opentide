# workspace_not_found

`opentide new` ran outside a workspace: neither `.opentide/` nor `objects/` is there.

Exit 1, as `failure.code`. `new` writes only into a workspace, the folder `--repo` names or the one discovery finds, so a stray run in your home directory cannot make it a workspace that every folder below it would discover.

## Example

```text
cd ~ && opentide new threat --name "Credential Dumping"
```

## How to fix

Run it from inside your detection repository, or pass `--repo path/to/detections`. To start a new one, run `opentide setup`. `opentide doctor` applies the same test as its `workspace` check.
