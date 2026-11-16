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
    "opentide-parse": ("crates/opentide-parse", [("serde", None)]),
    "opentide-kql": ("crates/opentide-kql", [("opentide-parse", None)]),
    "opentide-kuery": ("crates/opentide-kuery", [("opentide-parse", None)]),
    "opentide-schema": ("crates/opentide-schema", []),
    "opentide-schema-derive": ("crates/opentide-schema-derive", []),
    "opentide-analysis": (
        "crates/opentide-analysis",
        [
            ("opentide-kql", None),
            ("opentide-kuery", None),
            ("opentide-parse", None),
            ("opentide-schema", None),
        ],
    ),
    "opentide-cli": ("crates/opentide-cli", [("opentide-analysis", None)]),
    "opentide": ("crates/opentide", [("opentide-cli", None)]),
    "opentide-native": ("bindings/python", [("opentide", None)]),
    "opentide-node": ("bindings/node", [("opentide", None)]),
    "opentide-wasm": ("crates/opentide-wasm", [("opentide-analysis", None)]),
    # A test-only dependency affects the crate that tests with it.
    "xtask": ("xtask", [("opentide-schema", "dev")]),
    "opentide-compare": ("crates/opentide-compare", []),
    # An anchor (changes.ANCHORS): built with every pull request's crates.
    "opentide-connectors": ("crates/opentide-connectors", [("opentide-schema", None)]),
}
MEMBERS = sorted(CRATES)
ABOVE_PARSE = {
    "opentide-parse",
    "opentide-kql",
    "opentide-kuery",
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
    outputs = plan("crates/opentide-parse/src/lib.rs")
    assert set(outputs["crates"].split()) == ABOVE_PARSE
    # A Rust-only change builds no wheel and runs no pytest: the Rust tests
    # cover it (the maintainer's rule); of the specialised jobs, the parser
    # layer runs the WebAssembly builds (WASI and browser) alone.
    assert on(outputs) == {"rust", "lint", "wasm"}
    # The anchors are built, so the third-party features resolve as on the
    # push that saved the compiler cache; only the affected crates' tests run.
    built = set(outputs["packages"].replace("-p ", "").split())
    assert built == ABOVE_PARSE | {"opentide-connectors"}
    assert "opentide-connectors" not in outputs["filter"]
    assert outputs["filter"].count("package(=") == len(ABOVE_PARSE)


@pytest.mark.parametrize(
    "path",
    [
        "crates/opentide-kuery/src/lib.rs",
        "crates/opentide-kql/src/parse.rs",
        "crates/opentide-parse/src/lib.rs",
        "crates/opentide-parse/src/parser.rs",
        "highlights/spec.toml",
    ],
)
def test_the_parser_layer_runs_the_webassembly_builds(path: str) -> None:
    # A known path, not the fail-open of an unknown one: the `wasm` job
    # (browser, WASI server and command line) without the TypeScript client's
    # native tests, and no other specialised job.
    outputs = plan(path)
    assert outputs["wasm"] == "true"
    assert outputs["ts_packages"] == "false"
    assert outputs["node"] == "false"


@pytest.mark.parametrize(
    "path",
    [
        "docs/usage/configuration.md",
        "crates/opentide-schema/src/lib.rs",
        "crates/opentide-cli/src/main.rs",
        "highlights/test/embedded.test.mjs",
    ],
)
def test_other_changes_skip_the_webassembly_builds(path: str) -> None:
    outputs = plan(path)
    assert outputs["wasm"] == "false"
    assert outputs["ts_packages"] == "false"


@pytest.mark.parametrize(
    "path",
    [
        "crates/opentide-wasm/src/lib.rs",
        "scripts/engine/build-wasm.sh",
        "vendor/memmap2/src/lib.rs",
    ],
)
def test_the_webassembly_job_runs_on_its_own_paths(path: str) -> None:
    assert plan(path)["wasm"] == "true"


def test_the_typescript_packages_run_their_native_tests() -> None:
    outputs = plan("packages/lsp-client/src/index.ts")
    assert outputs["wasm"] == "true"
    assert outputs["ts_packages"] == "true"
    assert outputs["rust"] == "false"


def test_a_pull_request_that_changes_a_workflow_runs_the_browser_build() -> None:
    assert plan(".github/workflows/ci.yml")["wasm"] == "true"


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


def test_a_test_only_dependency_counts() -> None:
    assert "xtask" in plan("crates/opentide-schema/src/lib.rs")["crates"].split()


@pytest.mark.parametrize(
    "path", ["Cargo.lock", ".github/workflows/ci.yml", "rust-toolchain.toml", "a/new/place.txt"]
)
def test_shared_configuration_and_unknown_paths_mark_everything(path: str) -> None:
    outputs = plan(path)
    assert outputs["packages"] == "--workspace"
    expected = {"rust", "python", "node", "wasm", "ts_packages", "docs", "deny", "facade"}
    assert expected <= on(outputs)


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


def test_a_wasm_script_alone_runs_the_wasm_job_and_its_clippy() -> None:
    """`wasm` without `rust`: engine-lint runs its wasm32 clippy alone (ci.yml)."""
    for path in ("scripts/engine/build-wasm.sh", "scripts/engine/wasm-smoke.mjs"):
        outputs = plan(path)
        assert outputs["wasm"] == "true", path
        assert outputs["rust"] == "false", path


def test_the_browser_module_runs_the_typescript_client_tests() -> None:
    assert plan("crates/opentide-wasm/src/lib.rs")["ts_packages"] == "true"


@pytest.mark.parametrize(
    ("path", "checks"),
    [
        ("src/opentide/data/vocabulary/mitre/attack.vocab.toml", {"vocab"}),
        ("bindings/python/src/sdk.rs", {"stubs"}),
        ("crates/opentide/src/lib.rs", {"stubs"}),
        ("src/opentide/_native/models.pyi", {"stubs"}),
        ("xtask/src/stubs.rs", {"stubs"}),
        ("src/opentide/data/pins/specifications.toml", {"vocab"}),
        ("data/specifications.lock.json", {"vocab"}),
        ("xtask/src/vocab/sync.rs", {"vocab"}),
        ("crates/opentide-schema/src/objects/tide.rs", {"fields", "schema_ui", "stubs"}),
        ("xtask/src/spec_fields.rs", {"fields"}),
        ("crates/opentide-schema/src/lib.rs", {"schema_ui", "stubs"}),
        ("crates/opentide-schema/tests/ui/missing_field.rs", {"schema_ui", "stubs"}),
        ("crates/opentide-schema/Cargo.toml", {"schema_ui", "stubs"}),
        ("crates/opentide-schema-derive/src/lib.rs", {"schema_ui", "stubs"}),
        # Not their inputs: another crate, another xtask command.
        ("crates/opentide-kql/src/lib.rs", set()),
        ("xtask/src/codegen.rs", set()),
        ("src/opentide/data/vocabulary/README.md", set()),
        # Shared configuration runs every check, as a push does.
        ("Cargo.lock", {"vocab", "fields", "schema_ui", "stubs"}),
        (".github/workflows/ci.yml", {"vocab", "fields", "schema_ui", "stubs"}),
    ],
)
def test_build_s_checks_run_when_their_inputs_change(path: str, checks: set[str]) -> None:
    """`build`'s specifications and compile-fail checks read these outputs."""
    assert on(plan(path)) & set(changes.CHECKS) == checks


def test_a_push_runs_every_check() -> None:
    dirs, _ = changes.workspace_graph(metadata())
    full = changes.plan_run({"EVENT": "push"}, metadata()).outputs(dirs)
    assert {full[check] for check in changes.CHECKS} == {"true"}


def test_a_stubs_input_runs_the_stubs_job_alone() -> None:
    """An opentide-schema change runs `stubs`, not the wheel job nor pytest."""
    outputs = plan("crates/opentide-schema/src/python.rs")
    assert outputs["stubs"] == "true"
    assert outputs["native"] == "false"
    assert outputs["python"] == "false"
