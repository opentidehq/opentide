# sysdig_list_self_reference

A block list names itself as one of its items, so its own name stays in the expanded condition.

Severity: warning. Reported by the analysis engine on a Sysdig rule (`sysdig`): an item of one of the block's `lists` is that list's own name. `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it; `opentide validate` does not fail on it. Falco loads the rule: it flattens a list with the lists defined before it only, and its `resolve_list` pass never re-scans the items it has just inserted, so the name is left in the text as a literal value. On Sysdig Secure that literal then resolves against any tenant list of the same name, or matches the bare string. A list naming a later block list is not this advisory: the later list's own pass expands it, as Falco does.

## Example

```yaml
configurations:
  sysdig:
    condition: spawned_process and proc.name in (shells)
    lists:
      - name: shells
        items: [bash, zsh, shells]   # deploys as proc.name in ( bash, zsh, shells )
```

## How to fix

Remove the item, or name the other list you meant. To extend a list with another, define that list before it in the block, or after it if you prefer: both expand.

```yaml
    lists:
      - name: more_shells
        items: [fish, ksh]
      - name: shells
        items: [bash, zsh, more_shells]   # deploys as proc.name in ( bash, zsh, fish, ksh )
```
