"""scripts/ci/changes.py: what a CI run checks (ci.yml's `changes` job).

A pull request is checked where it changed; shared configuration and any path
no rule knows mark everything (fail open); a push, Run workflow and the
nightly mark everything. The workspace is synthetic (cargo metadata's shape).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "changes", Path(__file__).resolve().parents[2] / "scripts" / "ci" / "changes.py"
)
assert _SPEC is not None and _SPEC.loader is not None
changes: ModuleType = importlib.util.module_from_spec(_SPEC)
# Registered first: its dataclass looks its module up.
sys.modules.setdefault("changes", changes)
_SPEC.loader.exec_module(changes)

ROOT = "/repo"
# name -> (directory, [(dependency, kind)]); a dependency outside the
# workspace (serde) has no path and never counts.
CRATES: dict[str, tuple[str, list[tuple[str, str | None]]]] = {
    "opentide-syntax": ("crates/opentide-syntax", [("serde", None)]),
    "opentide-kql": ("crates/opentide-kql", [("opentide-syntax", None)]),
    "opentide-schema": ("crates/opentide-schema", []),
    "opentide-analysis": (
        "crates/opentide-analysis",
        [("opentide-kql", None), ("opentide-schema", None)],
    ),
    "opentide-cli": ("crates/opentide-cli", [("opentide-analysis", None)]),
    "opentide": ("crates/opentide", [("opentide-cli", None)]),
    "opentide-native": ("bindings/python", [("opentide", None)]),
    "opentide-node": ("bindings/node", [("opentide", None)]),
    "opentide-wasm": ("crates/opentide-wasm", [("opentide-analysis", None)]),
    # A test-only dependency affects the crate that tests with it.
    "xtask": ("xtask", [("opentide-schema", "dev")]),
    "opentide-compare": ("crates/opentide-compare", []),
}
MEMBERS = sorted(CRATES)
ABOVE_SYNTAX = {
    "opentide-syntax",
    "opentide-kql",
    "opentide-analysis",
    "opentide-cli",
    "opentide",
    "opentide-native",
    "opentide-node",
    "opentide-wasm",
}


def _id(name: str) -> str:
    return f"path+file://{ROOT}/{CRATES[name][0]}#{name}@0.1.0"


def metadata() -> dict[str, Any]:
    packages: list[dict[str, Any]] = []
    for name, (directory, deps) in CRATES.items():
        packages.append(
            {
                "id": _id(name),
                "name": name,
                "manifest_path": f"{ROOT}/{directory}/Cargo.toml",
                "dependencies": [
                    {
                        "name": dep,
                        "kind": kind,
                        **({"path": f"{ROOT}/{CRATES[dep][0]}"} if dep in CRATES else {}),
                    }
                    for dep, kind in deps
                ],
            }
        )
    # A registry package `cargo metadata` lists without --no-deps: no member.
    packages.append(
        {
            "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0",
            "name": "serde",
            "manifest_path": "/home/.cargo/registry/serde-1.0.0/Cargo.toml",
            "dependencies": [],
        }
    )
    return {
        "workspace_root": ROOT,
        "workspace_members": [_id(name) for name in CRATES],
        "packages": packages,
    }


def plan(*paths: str) -> dict[str, str]:
    dirs, rdeps = changes.workspace_graph(metadata())
    return changes.plan_for_paths(paths, dirs, rdeps).outputs(dirs)


def on(outputs: dict[str, str]) -> set[str]:
    return {key for key, value in outputs.items() if value == "true"}


def test_a_docs_only_change_runs_docs_alone() -> None:
    outputs = plan("docs/usage/configuration.md")
    assert on(outputs) == {"docs"}
    assert outputs["crates"] == ""


def test_a_leaf_crate_runs_itself_and_its_reverse_dependencies() -> None:
    outputs = plan("crates/opentide-syntax/src/lib.rs")
    assert set(outputs["crates"].split()) == ABOVE_SYNTAX
    # A Rust-only change builds no wheel and runs no pytest: the Rust tests
    # cover it (the maintainer's rule); no specialised job either.
    assert on(outputs) == {"rust", "build", "lint"}
    assert outputs["packages"].startswith("-p ")


def test_the_python_surface_runs_the_python_job() -> None:
    for path in (
        "src/opentide/sdk.py",
        "bindings/python/src/lib.rs",
        "crates/opentide/src/lib.rs",
        "tests/test_sdk/test_workspace.py",
        "pyproject.toml",
    ):
        assert plan(path)["python"] == "true", path
    assert plan("crates/opentide-cli/src/lib.rs")["python"] == "false"


def test_the_tests_that_need_no_wheel_run_without_the_python_job() -> None:
    assert on(plan("tests/test_ci/test_workflows.py")) == {"ci", "pylint", "lint"}
    assert on(plan("tests/test_docs/test_docs_mdx.py")) == {"docs", "pylint", "lint"}
    assert plan("tests/test_docs/test_sdk_snippets.py")["python"] == "true"


def test_a_crate_below_no_heavy_crate_runs_one_partition() -> None:
    outputs = plan("crates/opentide-compare/src/lib.rs")
    assert outputs["crates"] == "opentide-compare"
    assert outputs["partitions"] == "[1]"


def test_a_test_only_dependency_counts() -> None:
    assert "xtask" in plan("crates/opentide-schema/src/lib.rs")["crates"].split()


@pytest.mark.parametrize(
    "path", ["Cargo.lock", ".github/workflows/ci.yml", "rust-toolchain.toml", "a/new/place.txt"]
)
def test_shared_configuration_and_unknown_paths_mark_everything(path: str) -> None:
    outputs = plan(path)
    assert outputs["packages"] == "--workspace"
    assert {"rust", "python", "node", "wasi", "docs", "deny", "facade"} <= on(outputs)


@pytest.mark.parametrize(
    ("base", "head", "labels", "release"),
    [
        ("development", "integration/unified-core", [], True),
        ("development", "release/1.0", [], True),
        ("integration/unified-core", "fix/x", ["release"], True),
        ("integration/unified-core", "fix/x", [], False),
    ],
)
def test_release_pull_requests(base: str, head: str, labels: list[str], release: bool) -> None:
    assert changes.is_release_pr(base, head, labels) is release


@pytest.mark.parametrize(
    ("event", "scope", "mode"),
    [
        ("push", "", "full"),
        ("schedule", "", "nightly"),
        ("workflow_dispatch", "nightly", "nightly"),
    ],
)
def test_pushes_and_the_nightly_check_everything(event: str, scope: str, mode: str) -> None:
    result: Any = changes.plan_run({"EVENT": event, "SCOPE": scope}, metadata())
    assert result.mode == mode
    assert set(result.crates) == set(MEMBERS)
