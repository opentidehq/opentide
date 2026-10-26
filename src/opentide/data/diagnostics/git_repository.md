# git_repository

The workspace is in a git repository, and its default branch (`origin/HEAD`).

Reported by `opentide doctor`. Warns when it is not a repository, or `origin/HEAD` is not set.

## Example

```text
! ./ is not in a git repository · git_repository
  → git init ./
```

## How to fix

Run the command it prints: `git init` for a new repository, or `git remote set-head origin --auto` when `origin/HEAD` is unset.
