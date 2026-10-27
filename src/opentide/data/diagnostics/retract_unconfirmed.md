# retract_unconfirmed

`share retract` would delete a remote event, and was not confirmed.

Exit 1, as `failure.code` and `preflight`. Nothing was deleted.

## Example

```text
opentide share retract --uuid 00000000-0000-4000-8003-000000000001
```

## How to fix

Pass `--yes` to delete the remote event.
