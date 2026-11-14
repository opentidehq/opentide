"""The matrices of ci.yml, as the contract tests read them.

A matrix is static (its axes are lists) except where `changes` decides it:
``rust-tests`` reads its partitions from an output
(``${{ fromJSON(needs.changes.outputs.partitions) }}``). Such an axis is one
cell whose value is the expression itself: the tests that read a matrix need
its runners and names, which an expression axis does not change.
"""

from __future__ import annotations

from typing import Any


def cells(job: dict[str, Any]) -> list[dict[str, str]]:
    """The job's matrix cells: the product of its axes, or its `include`
    entries when it has no axes; one empty cell without a matrix."""
    matrix = (job.get("strategy") or {}).get("matrix") or {}
    if isinstance(matrix, str):
        return [{}]
    include = matrix.get("include")
    assert not isinstance(include, str), f"an `include` expression: {include}"
    axes = {k: v for k, v in matrix.items() if k not in ("include", "exclude")}
    found: list[dict[str, str]] = [{}]
    for name, values in axes.items():
        # An expression axis (`fromJSON(...)`): one cell stands for its values.
        values = [values] if isinstance(values, str) else values
        found = [{**cell, name: str(value)} for cell in found for value in values]
    if not axes and include:
        found = [{str(k): str(v) for k, v in entry.items()} for entry in include]
    return found
