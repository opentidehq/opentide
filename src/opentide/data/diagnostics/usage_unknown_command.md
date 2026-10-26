# usage_unknown_command

The command line names a command that does not exist.

Exit 2, as `failure.code`. `failure.suggestion` names the closest command.

## Example

```text
opentide valdiate
```

## How to fix

Run the command `did you mean` names, or `opentide --help` for the list. In an agent, `opentide commands --json` prints the whole command tree.
