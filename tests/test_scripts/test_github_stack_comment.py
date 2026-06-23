"""Tests for stack comment chain building (no GitHub API)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_MODULE = Path(__file__).resolve().parents[2] / "scripts" / "github_stack_comment.py"
_spec = importlib.util.spec_from_file_location("github_stack_comment", _MODULE)
assert _spec and _spec.loader
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
build_stack_chain = _mod.build_stack_chain


def _pr(
    number: int,
    head: str,
    base: str,
    *,
    state: str = "OPEN",
) -> dict:
    return {
        "number": number,
        "title": head,
        "url": f"https://github.com/org/repo/pull/{number}",
        "state": state,
        "baseRefName": base,
        "headRefName": head,
        "isDraft": False,
    }


def test_build_stack_chain_three_deep() -> None:
    open_prs = [
        _pr(10, "feat/a", "development"),
        _pr(11, "feat/b", "feat/a"),
        _pr(12, "feat/c", "feat/b"),
    ]
    chain = build_stack_chain(open_prs[1], open_prs)
    assert [p["number"] for p in chain] == [10, 11, 12]


def test_build_stack_chain_standalone_on_trunk() -> None:
    open_prs = [_pr(5, "fix/foo", "development")]
    chain = build_stack_chain(open_prs[0], open_prs)
    assert [p["number"] for p in chain] == [5]
