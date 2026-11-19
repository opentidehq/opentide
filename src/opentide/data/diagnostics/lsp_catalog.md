# lsp_catalog

opentide can generate the language server's catalog for this workspace, and a committed copy is current.

Reported by `opentide doctor`. `opentide lsp start`, the `opentide-lsp` binary on its own and `opentide tui` check objects with the catalog they generate in memory, each time they start, from the models they were built with and the workspace's configuration; nothing is cached. No program reads the copy `opentide generate schemas` writes to `.opentide/lsp/catalogs/generated/`: it is there for other tools. Warns when a committed copy does not parse or comes from another opentide version.

## Example

```text
! The language-server catalog committed in .opentide/lsp/catalogs/generated is from opentide 0.18.0, not 0.19.0 · lsp_catalog
  → opentide generate schemas
```

## How to fix

For a committed copy, run `opentide generate schemas` (or `opentide generate`) and commit the files it writes, so a tool that reads them sees this opentide's catalog, or delete the folder: opentide and its language server do not read it.
