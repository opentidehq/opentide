# interrupted

The command was stopped before it finished: an `opentide serve` client cancelled the run.

Exit 130, as Ctrl-C at a terminal exits. The command's own cleanup ran first (an open search is stopped, a file being written is not left half-written), so whatever it had not done yet was not done. A command stopped this way prints no document of its own, so `opentide serve` answers with one that carries this code.

## Example

```json
{"jsonrpc": "2.0", "method": "$/cancelRequest", "params": {"id": 7}}
```

## How to fix

Nothing is broken. Run the command again when you need its result; a `validate` or `lint` that was cancelled wrote nothing.
