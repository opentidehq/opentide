# engine_not_ported

`OPENTIDE_ENGINE=rust` asked for the Rust implementation of a command that has none yet. opentide is moving its commands from Python to Rust one at a time; until a command has a Rust implementation, only its Python one runs.

Exit 2, as `failure.code`, with `failure.argument` `OPENTIDE_ENGINE`.

## Example

```text
error: opentide validate has no Rust implementation yet: unset OPENTIDE_ENGINE, or set it to python or compare.
```

## How to fix

Unset `OPENTIDE_ENGINE`, or set it to `python` (the default) or `compare`, which runs the Python implementation alone where there is no Rust one. This is not the analysis engine failing to load: that is `engine_unavailable`.
