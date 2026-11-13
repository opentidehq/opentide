"""Print the engine state the parity dashboard reads (UC-X.2, #844).

``cargo xtask parity dashboard --engines FILE`` takes a JSON document
``{"rust": [[word, ...], ...], "flipped": [[word, ...], ...]}``: the command
paths that have a Rust implementation, and those whose default is Rust. The
dispatch table is ``RUST_COMMANDS`` in ``src/opentide/cli/engines.py``
(UC-0.7, #805), a dict literal keyed by command-path tuples. This script reads
it with :mod:`ast`, without importing opentide, so the dashboard job needs no
Python environment. The flipped paths are those ``DEFAULT_ENGINES`` in
``engine_defaults.py`` beside it maps to ``rust`` (plan §7): ``tui`` since
UC-6.0d and ``mcp start`` since UC-6.0c (#841).

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
#: The defaults table, in ``engine_defaults.py`` beside the dispatch table.
DEFAULTS_FILE = "engine_defaults.py"
DEFAULTS = "DEFAULT_ENGINES"


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


def _table(source: str, name: str) -> ast.Dict | None:
    """The dict literal assigned to *name* in *source*; ``None`` when nothing is."""
    for statement in ast.parse(source).body:
        target: ast.expr | None = None
        value: ast.expr | None = None
        if isinstance(statement, ast.AnnAssign):
            target, value = statement.target, statement.value
        elif isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target, value = statement.targets[0], statement.value
        if not (isinstance(target, ast.Name) and target.id == name):
            continue
        if not isinstance(value, ast.Dict) or any(key is None for key in value.keys):
            raise EngineStateError(f"{name} is not a dict literal: the dashboard cannot read it")
        return value
    return None


def flipped_commands(source: str) -> list[list[str]]:
    """The command paths ``DEFAULT_ENGINES`` in *source* maps to ``rust``, sorted.

    A value is the string ``"rust"`` or the module's ``RUST`` constant.
    """
    table = _table(source, DEFAULTS)
    if table is None:
        raise EngineStateError(f"no {DEFAULTS} assignment")
    flipped = []
    for key, value in zip(table.keys, table.values, strict=True):
        rust = (isinstance(value, ast.Constant) and value.value == "rust") or (
            isinstance(value, ast.Name) and value.id == "RUST"
        )
        if rust and key is not None:
            flipped.append(_path(key))
    return sorted(flipped)


def rust_commands(source: str) -> list[list[str]]:
    """The command paths the ``RUST_COMMANDS`` literal in *source* names, sorted."""
    table = _table(source, TABLE)
    if table is None:
        raise EngineStateError(f"no {TABLE} assignment")
    return sorted(_path(key) for key in table.keys if key is not None)


def engine_state(source: str, defaults: str | None = None) -> dict[str, list[list[str]]]:
    """The document ``--engines`` reads; *defaults* is ``engine_defaults.py``'s source."""
    flipped = [] if defaults is None else flipped_commands(defaults)
    return {"rust": rust_commands(source), "flipped": flipped}


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else ENGINES
    defaults_path = path.with_name(DEFAULTS_FILE)
    try:
        defaults = defaults_path.read_text(encoding="utf-8") if defaults_path.is_file() else None
        state = engine_state(path.read_text(encoding="utf-8"), defaults)
    except (OSError, SyntaxError, EngineStateError) as error:
        print(f"parity_engines: {path}: {error}", file=sys.stderr)
        return 2
    print(json.dumps(state, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
