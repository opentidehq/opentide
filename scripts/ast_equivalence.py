#!/usr/bin/env python3
"""List changed Python files whose behaviour may differ from a git revision.

A mechanical change -- formatting, splitting long strings, sorting imports,
modernising annotations, lint autofixes -- should leave a module's syntax tree
alone. Python folds implicit string concatenation while parsing, so a string
split across lines parses to the same constant. This script compares each
changed file's AST with the same file at *base*, ignoring imports and type
annotations, and prints the files that still differ. Review every one of them.

    uv run python scripts/ast_equivalence.py origin/development
    uv run python scripts/ast_equivalence.py HEAD --diff   # show what changed

Exit status: 0 when every changed file is equivalent, 1 otherwise.
"""

from __future__ import annotations

import argparse
import ast
import difflib
import subprocess
import sys


class _Normalise(ast.NodeTransformer):
    """Drop what a mechanical change may legitimately rewrite."""

    def visit_Import(self, node: ast.Import) -> None:
        return None

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        return None

    def visit_arg(self, node: ast.arg) -> ast.arg:
        node.annotation = None
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)
        node.returns = None
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        self.generic_visit(node)
        node.returns = None
        return node

    def visit_AnnAssign(self, node: ast.AnnAssign) -> ast.AnnAssign:
        self.generic_visit(node)
        node.annotation = ast.Constant(value=None)
        return node


def normalised_dump(source: str) -> list[str]:
    """The AST of *source* without imports or annotations, one node per line."""
    tree = _Normalise().visit(ast.parse(source))
    return ast.dump(tree, include_attributes=False, indent=1).splitlines()


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def changed_python_files(base: str) -> list[str]:
    """Python files that differ between *base* and the working tree, still present."""
    names = _git("diff", "--name-only", "--diff-filter=M", base, "--", "*.py").split()
    return sorted(names)


def compare(base: str, path: str) -> list[str]:
    """A unified diff of the normalised trees; empty when they are equivalent."""
    old = _git("show", f"{base}:{path}")
    with open(path, encoding="utf-8") as handle:
        new = handle.read()
    return list(
        difflib.unified_diff(
            normalised_dump(old), normalised_dump(new), f"{base}:{path}", path, lineterm=""
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("base", nargs="?", default="HEAD", help="git revision to compare with")
    parser.add_argument("--diff", action="store_true", help="print the AST differences")
    args = parser.parse_args(argv)

    differing = 0
    for path in changed_python_files(args.base):
        diff = compare(args.base, path)
        if not diff:
            continue
        differing += 1
        changed = sum(1 for line in diff if line[:1] in "+-") - 2
        sys.stdout.write(f"{path}: {changed} AST line(s) differ\n")
        if args.diff:
            sys.stdout.write("\n".join(diff) + "\n")
    return 1 if differing else 0


if __name__ == "__main__":
    raise SystemExit(main())
