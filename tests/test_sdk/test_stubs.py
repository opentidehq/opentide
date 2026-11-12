"""``opentide/_native/sdk.pyi`` matches the compiled ``opentide._native.sdk`` (UC-5.2, #837).

ty checks ``opentide.sdk`` against the stub, so a method the stub lacks or
misnames would type-check and fail at run time.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import opentide._native.sdk as native

STUB = Path(__file__).resolve().parents[2] / "src" / "opentide" / "_native" / "sdk.pyi"


def _stub() -> ast.Module:
    return ast.parse(STUB.read_text(encoding="utf-8"))


def _parameters(function: ast.FunctionDef) -> list[str]:
    arguments = function.args
    names = [a.arg for a in [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]]
    return [name for name in names if name not in {"self", "cls"}]


def test_the_stub_names_every_public_name_of_the_module() -> None:
    declared = {
        node.name for node in _stub().body if isinstance(node, ast.ClassDef | ast.FunctionDef)
    }
    public = {name for name in dir(native) if not name.startswith("_")}
    assert declared == public


def test_each_method_takes_the_stubs_parameters() -> None:
    classes = {node.name: node for node in _stub().body if isinstance(node, ast.ClassDef)}
    stubbed = {
        node.name: node for node in classes["Workspace"].body if isinstance(node, ast.FunctionDef)
    }
    runtime = {name for name in dir(native.Workspace) if not name.startswith("_")}
    assert set(stubbed) == runtime
    for name, function in stubbed.items():
        member = getattr(native.Workspace, name)
        if isinstance(member, property) or not callable(member):
            continue
        signature = inspect.signature(member)
        expected = [p for p in signature.parameters if p not in {"self", "$self"}]
        assert _parameters(function) == expected, name
    run_json = next(
        n for n in _stub().body if isinstance(n, ast.FunctionDef) and n.name == "run_json"
    )
    assert _parameters(run_json) == list(inspect.signature(native.run_json).parameters)
