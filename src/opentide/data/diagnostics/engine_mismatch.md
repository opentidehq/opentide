# engine_mismatch

`OPENTIDE_ENGINE=compare` ran the command's Python and Rust implementations on the same input, each on its own copy of the workspace, and they did not do the same: a different exit code, stdout or stderr, or a file one of them created, changed or deleted and the other did not.

Exit 70, as `failure.code`. The message names the diff report, a JSON file in opentide's state directory (`$XDG_STATE_HOME/opentide/compare/` on Linux), which lists each difference with where it is and both sides.

## Example

```text
error: The Python and Rust implementations of opentide validate differ (2 differences); the report is /home/me/.local/state/opentide/compare/20261108T101500123456Z.json
```

## How to fix

Nothing in your workspace is wrong: this is a difference between two implementations of opentide, and the Python one is the reference. Run the command again without `OPENTIDE_ENGINE` (or with `OPENTIDE_ENGINE=python`) to get its usual result, and report the difference at https://github.com/opentidehq/opentide/issues with the report attached; read it first, it holds parts of the command's output.
