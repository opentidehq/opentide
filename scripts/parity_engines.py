"""Print the engine state the parity dashboard reads (UC-X.2, #844).

``cargo xtask parity dashboard --engines FILE`` takes a JSON document
``{"rust": [[word, ...], ...], "flipped": [[word, ...], ...]}``: the command
paths that have a Rust implementation, and those whose default is Rust. The
dispatch table is ``RUST_COMMANDS`` in ``src/opentide/cli/engines.py``
(UC-0.7, #805), a dict literal keyed by command-path tuples. This script reads
it with :mod:`ast`, without importing opentide, so the dashboard job needs no
Python environment. No command is flipped yet: the engine module has no
default other than Python (plan §7 adds one), so ``flipped`` is empty.

Usage: ``python3 scripts/parity_engines.py [ENGINES_PY] > engines.json``
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINES = ROOT / "src" / "opentide" / "cli" / "engines.py"
TABLE = "RUST_COMMANDS"


class EngineStateError(ValueError):
    """The dispatch table is missing or is not a literal this script can read."""


def _path(node: ast.expr) -> list[str]:
    # An empty tuple is the root command, `opentide` itself.
    if not isinstance(node, ast.Tuple):
        raise EngineStateError(f"{TABLE}: a key is not a tuple of words (line {node.lineno})")
    words: list[str] = []
    for element in node.elts:
        if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
            raise EngineStateError(f"{TABLE}: a key holds a non-string (line {node.lineno})")
        words.append(element.value)
    return words


def rust_commands(source: str) -> list[list[str]]:
    """The command paths the ``RUST_COMMANDS`` literal in *source* names, sorted."""
    for statement in ast.parse(source).body:
        target: ast.expr | None = None
        value: ast.expr | None = None
        if isinstance(statement, ast.AnnAssign):
            target, value = statement.target, statement.value
        elif isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target, value = statement.targets[0], statement.value
        if not (isinstance(target, ast.Name) and target.id == TABLE):
            continue
        if not isinstance(value, ast.Dict) or any(key is None for key in value.keys):
            raise EngineStateError(f"{TABLE} is not a dict literal: the dashboard cannot read it")
        return sorted(_path(key) for key in value.keys if key is not None)
    raise EngineStateError(f"no {TABLE} assignment")


def engine_state(source: str) -> dict[str, list[list[str]]]:
    """The document ``--engines`` reads."""
    return {"rust": rust_commands(source), "flipped": []}


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else ENGINES
    try:
        state = engine_state(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, EngineStateError) as error:
        print(f"parity_engines: {path}: {error}", file=sys.stderr)
        return 2
    print(json.dumps(state, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
