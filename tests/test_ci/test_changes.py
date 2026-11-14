"""scripts/ci/changes.py: what a CI run checks (ci.yml's `changes` job).

A pull request is checked where it changed: its paths map to areas (each a job
of ci.yml) and to workspace crates, a changed crate brings its reverse
dependencies, and the Python jobs run when the binding (opentide-native) is
reached. Shared configuration and any path no rule knows mark everything (fail
open). A push, Run workflow and the nightly mark everything; a release pull
request marks everything and the release tier.

The workspace here is synthetic (``cargo metadata``'s shape, no cargo): the
real one's crates are named, so the facade's features and the heavy crates
read as they do in CI.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from tests.test_ci.ci_steps import changes, ci_jobs

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
BOOLEANS = {
    "release",
    "build",
    "rust",
    "python",
    "lint",
    "docs",
    "node",
    "wasi",
    "grammars",
    "textmate",
    "gitlab",
    "facade",
    "deny",
}


def _id(name: str) -> str:
    return f"path+file://{ROOT}/{CRATES[name][0]}#{name}@0.1.0"


def _metadata() -> dict[str, Any]:
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


def _graph() -> tuple[dict[str, str], dict[str, set[str]]]:
    return changes().workspace_graph(_metadata())


def _plan(*paths: str) -> Any:
    dirs, rdeps = _graph()
    return changes().plan_for_paths(list(paths), dirs, rdeps)


def _outputs(*paths: str) -> dict[str, str]:
    return _plan(*paths).outputs(MEMBERS)


def _on(outputs: dict[str, str]) -> set[str]:
    """The boolean outputs that are true."""
    return {key for key in BOOLEANS if outputs[key] == "true"}


# ---- the workspace graph ------------------------------------------------------


def test_the_graph_names_each_members_directory_and_its_reverse_dependencies() -> None:
    dirs, rdeps = _graph()
    assert dirs == {name: directory for name, (directory, _) in CRATES.items()}
    assert "serde" not in dirs and "serde" not in rdeps
    assert rdeps["opentide-syntax"] == {"opentide-kql"}
    assert rdeps["opentide-schema"] == {"opentide-analysis", "xtask"}
    assert rdeps["opentide"] == {"opentide-native", "opentide-node"}
    assert rdeps["opentide-compare"] == set()


def test_the_reverse_closure_is_transitive() -> None:
    _, rdeps = _graph()
    assert changes().reverse_closure(["opentide-syntax"], rdeps) == ABOVE_SYNTAX
    assert changes().reverse_closure(["opentide-native"], rdeps) == {"opentide-native"}
    assert changes().reverse_closure([], rdeps) == set()


@pytest.mark.parametrize(
    ("path", "crate"),
    [
        ("crates/opentide-cli/src/main.rs", "opentide-cli"),
        # A prefix of another crate's directory is not that crate.
        ("crates/opentide/src/lib.rs", "opentide"),
        ("bindings/python/src/lib.rs", "opentide-native"),
        ("xtask/src/main.rs", "xtask"),
        ("crates/testdata/conformance/x.kql", None),
        ("crates/CHANGELOG.md", None),
        ("Cargo.toml", None),
    ],
)
def test_a_path_belongs_to_the_crate_whose_directory_holds_it(path: str, crate: str | None) -> None:
    dirs, _ = _graph()
    assert changes().owning_crate(path, dirs) == crate


def test_the_deepest_directory_owns_a_path() -> None:
    dirs = {"outer": "crates/outer", "inner": "crates/outer/inner"}
    assert changes().owning_crate("crates/outer/inner/src/lib.rs", dirs) == "inner"
    assert changes().owning_crate("crates/outer/src/lib.rs", dirs) == "outer"


# ---- a pull request's paths ---------------------------------------------------


def test_a_docs_only_change_runs_the_docs_alone() -> None:
    outputs = _outputs("docs/cli/validate.md", "README.md", "AGENTS.md")
    assert _on(outputs) == {"docs"}
    assert outputs["crates"] == outputs["packages"] == outputs["features"] == ""
    assert outputs["mode"] == "pr"
    assert json.loads(outputs["partitions"]) == [1]


def test_a_leaf_crate_runs_its_own_tests_and_not_python() -> None:
    plan = _plan("crates/opentide-compare/src/lib.rs")
    assert plan.crates == {"opentide-compare"}
    outputs = plan.outputs(MEMBERS)
    assert _on(outputs) == {"rust", "lint", "build"}
    assert outputs["packages"] == "-p opentide-compare"
    assert outputs["features"] == ""
    # No heavy crate: one partition.
    assert json.loads(outputs["partitions"]) == [1]


def test_a_crate_brings_its_reverse_dependencies_and_python_through_the_binding() -> None:
    plan = _plan("crates/opentide-syntax/src/lib.rs")
    assert plan.crates == ABOVE_SYNTAX
    outputs = plan.outputs(MEMBERS)
    # opentide-native is reached: the Python suite and E2E run.
    assert {"rust", "python", "lint", "build"} <= _on(outputs)
    assert outputs["packages"] == " ".join(f"-p {c}" for c in sorted(ABOVE_SYNTAX))
    # The facade's features, as the workspace unifies them; not opentide-schema's,
    # which is not selected.
    assert outputs["features"] == f"--features {changes().FEATURES['opentide']}"
    assert json.loads(outputs["partitions"]) == [1, 2]


def test_features_are_named_only_for_the_selected_crates() -> None:
    outputs = _outputs("crates/opentide-schema/src/lib.rs")
    selected = outputs["packages"].split()[1::2]
    assert "opentide-schema" in selected and "xtask" in selected
    features = outputs["features"].removeprefix("--features ").split(",")
    assert "opentide-schema/python" in features
    for feature in features:
        assert feature.split("/")[0] in selected, feature
    only_xtask = changes().Plan(mode="pr", crates={"xtask"}).outputs(MEMBERS)
    assert only_xtask["features"] == ""


@pytest.mark.parametrize(
    "path",
    [
        "Cargo.lock",
        "Cargo.toml",
        "rust-toolchain.toml",
        ".cargo/config.toml",
        ".config/nextest.toml",
        "clippy.toml",
        ".github/workflows/ci.yml",
        ".github/actions/setup/action.yml",
        "scripts/ci/changes.py",
        "scripts/ci-local.sh",
        # No rule knows it: fail open.
        "somewhere/new.bin",
    ],
)
def test_shared_configuration_and_unknown_paths_mark_everything(path: str) -> None:
    plan = _plan("docs/index.md", path)
    assert plan.areas == set(changes().AREAS)
    assert plan.crates == set(MEMBERS)
    outputs = plan.outputs(MEMBERS)
    assert _on(outputs) == BOOLEANS - {"release"}
    assert outputs["packages"] == "--workspace"
    assert json.loads(outputs["partitions"]) == [1, 2]
    assert path in plan.reasons[-1]


@pytest.mark.parametrize(
    ("path", "areas"),
    [
        ("crates/opentide/src/lib.rs", {"facade"}),
        ("bindings/node/src/lib.rs", {"node"}),
        ("crates/opentide-wasm/src/lib.rs", {"wasi"}),
        ("crates/opentide-cli/src/render/ci.rs", {"gitlab"}),
        ("crates/opentide-cli/src/commands/setup/gitlab.rs", {"gitlab"}),
        ("crates/opentide-kql/Cargo.toml", {"deny"}),
        ("xtask/Cargo.toml", {"deny"}),
        ("crates/opentide-cli/src/main.rs", set()),
    ],
)
def test_a_crate_path_runs_the_specialised_job_it_is_about(path: str, areas: set[str]) -> None:
    specialised = {"facade", "node", "wasi", "gitlab", "deny", "grammars", "textmate", "docs"}
    plan = _plan(path)
    assert plan.areas & specialised == areas
    assert {"rust", "lint"} <= plan.areas


@pytest.mark.parametrize(
    ("path", "on", "crates"),
    [
        ("src/opentide/sdk.py", {"python", "lint", "build"}, set()),
        ("tests/test_sdk/test_x.py", {"python", "lint", "build"}, set()),
        ("uv.lock", {"python", "lint", "build"}, set()),
        ("hatch_build.py", {"python", "lint", "build"}, set()),
        ("CHANGELOG.md", {"python", "lint", "build"}, set()),
        (".agents/skills/rust/SKILL.md", {"lint"}, set()),
        (
            "tests/test_ci/test_gitlab_pipeline_lint.py",
            {"gitlab", "python", "lint", "build"},
            set(),
        ),
        ("scripts/install-gitlab-ci-linters.sh", {"gitlab", "build"}, set()),
        ("scripts/validate-docs.sh", {"docs", "lint"}, set()),
        ("scripts/engine/check-grammars.sh", {"grammars", "lint"}, set()),
        ("highlights/test/package.json", {"textmate"}, set()),
        ("editors/vscode/syntaxes/kql.json", {"textmate"}, set()),
        ("deny.toml", {"deny"}, set()),
        ("fuzz/fuzz_targets/kql.rs", {"deny"}, set()),
        ("packages/wasi-host/src/index.ts", {"wasi"}, set()),
        ("grammars/kql/grammar.js", None, {"opentide-syntax"}),
        ("src/opentide/data/vocabulary/x.toml", None, set(CRATES)),
        ("tests/golden/cases/x.toml", None, set(CRATES)),
        ("data/catalogs/kql.toml", None, set(CRATES)),
    ],
)
def test_a_path_outside_the_crates_maps_to_its_jobs(
    path: str, on: set[str] | None, crates: set[str]
) -> None:
    """``on`` is the exact set of true outputs (None: the crates decide it);
    ``crates`` are the crates the path names, before their reverse dependencies."""
    _, rdeps = _graph()
    plan = _plan(path)
    assert plan.crates == changes().reverse_closure(crates, rdeps)
    if on is not None:
        assert _on(plan.outputs(MEMBERS)) == on
    if crates:
        assert {"rust", "lint"} <= plan.areas


def test_the_first_rule_that_matches_wins() -> None:
    """src/opentide/data/ (bundled into the crates) before src/opentide/."""
    assert _plan("src/opentide/data/pins/threat.toml").crates == set(MEMBERS)
    assert _plan("src/opentide/cli.py").crates == set()


@pytest.mark.parametrize("area", ["rust", "python", "gitlab", "node"])
def test_an_area_whose_jobs_run_from_the_build_marks_the_build(area: str) -> None:
    plan = changes().Plan(mode="pr", areas={area})
    assert plan.outputs(MEMBERS)["build"] == "true"


@pytest.mark.parametrize("area", ["docs", "lint", "wasi", "grammars", "textmate", "facade", "deny"])
def test_an_area_that_builds_its_own_skips_the_build(area: str) -> None:
    plan = changes().Plan(mode="pr", areas={area})
    assert plan.outputs(MEMBERS)["build"] == "false"


# ---- release pull requests and the other events -------------------------------


@pytest.mark.parametrize(
    ("base", "head", "labels", "release"),
    [
        ("development", "integration/unified-core", [], True),
        ("development", "release/0.25", [], True),
        ("development", "feat/x", [], False),
        # Into integration or a train: an ordinary pull request.
        ("integration/unified-core", "release/0.25", [], False),
        ("train/0.25", "integration/unified-core", [], False),
        ("development", "feat/x", ["release"], True),
        ("integration/unified-core", "feat/x", ["release"], True),
        ("development", "feat/x", ["release-notes", "bug"], False),
    ],
)
def test_a_release_pull_request(base: str, head: str, labels: list[str], release: bool) -> None:
    assert changes().is_release_pr(base, head, labels) is release


def _run(
    monkeypatch: pytest.MonkeyPatch, env: dict[str, str], paths: list[str] | None = None
) -> Any:
    module = changes()
    seen: list[tuple[str, str]] = []

    def changed(base: str, head: str) -> list[str] | None:
        seen.append((base, head))
        return paths

    monkeypatch.setattr(module, "changed_paths", changed)
    plan = module.plan_run(env, _metadata())
    if env.get("EVENT") == "pull_request":
        assert seen == [(env.get("BASE_SHA", ""), env.get("HEAD_SHA", ""))]
    else:
        assert seen == [], "only a pull request reads its change"
    return plan


PULL = {
    "EVENT": "pull_request",
    "BASE_SHA": "a" * 40,
    "HEAD_SHA": "b" * 40,
    "BASE_REF": "development",
    "HEAD_REF": "feat/x",
    "LABELS": "[]",
}


def test_a_pull_request_is_checked_where_it_changed(monkeypatch: pytest.MonkeyPatch) -> None:
    plan = _run(monkeypatch, PULL, ["docs/index.md"])
    assert (plan.mode, plan.release, plan.areas, plan.crates) == ("pr", False, {"docs"}, set())


def test_a_pull_request_whose_change_cannot_be_read_checks_everything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _run(monkeypatch, PULL, None)
    assert plan.mode == "pr" and not plan.release
    assert plan.areas == set(changes().AREAS) and plan.crates == set(MEMBERS)


@pytest.mark.parametrize(
    "env",
    [
        {**PULL, "HEAD_REF": "integration/unified-core"},
        {**PULL, "HEAD_REF": "release/0.25"},
        {**PULL, "LABELS": '["bug", "release"]'},
    ],
)
def test_a_release_pull_request_checks_everything_and_the_release_tier(
    monkeypatch: pytest.MonkeyPatch, env: dict[str, str]
) -> None:
    plan = _run(monkeypatch, env, ["docs/index.md"])
    assert plan.mode == "pr" and plan.release
    outputs = plan.outputs(MEMBERS)
    assert _on(outputs) == BOOLEANS
    assert outputs["packages"] == "--workspace"


@pytest.mark.parametrize("labels", ["", "null"])
def test_a_pull_request_without_labels_is_no_release(
    monkeypatch: pytest.MonkeyPatch, labels: str
) -> None:
    plan = _run(monkeypatch, {**PULL, "LABELS": labels}, ["docs/index.md"])
    assert not plan.release


@pytest.mark.parametrize(
    ("event", "scope", "mode", "release"),
    [
        ("push", "", "full", False),
        ("workflow_dispatch", "", "full", False),
        ("workflow_dispatch", "full", "full", False),
        ("workflow_dispatch", "release", "full", True),
        ("workflow_dispatch", "nightly", "nightly", False),
        ("schedule", "", "nightly", False),
    ],
)
def test_every_other_run_checks_everything(
    monkeypatch: pytest.MonkeyPatch, event: str, scope: str, mode: str, release: bool
) -> None:
    plan = _run(monkeypatch, {"EVENT": event, "SCOPE": scope})
    assert (plan.mode, plan.release) == (mode, release)
    outputs = plan.outputs(MEMBERS)
    assert outputs["mode"] == mode
    assert _on(outputs) == (BOOLEANS if release else BOOLEANS - {"release"})
    assert outputs["packages"] == "--workspace"
    assert outputs["crates"] == " ".join(MEMBERS)
    assert json.loads(outputs["partitions"]) == [1, 2]


# ---- the outputs ci.yml reads -------------------------------------------------


def test_the_outputs_are_the_ones_ci_reads() -> None:
    outputs = _outputs("crates/opentide-kql/src/lib.rs")
    assert set(outputs) == BOOLEANS | {"mode", "crates", "packages", "features", "partitions"}
    assert set(outputs) == set(ci_jobs()["changes"]["outputs"])
    for key in BOOLEANS:
        assert outputs[key] in ("true", "false"), key
    # `-p NAME` pairs: the build reads them into an array.
    words = outputs["packages"].split()
    assert words[::2] == ["-p"] * (len(words) // 2)
    assert words[1::2] == sorted(words[1::2]) == outputs["crates"].split()


def test_every_area_runs_a_job_of_ci() -> None:
    """An area no job reads would mark nothing; a job reading an area
    changes.py does not write would never run."""
    text = json.dumps({job_id: job.get("if", "") for job_id, job in ci_jobs().items()})
    read = set(re.findall(r"needs\.changes\.outputs\.([\w-]+)", text))
    assert set(changes().AREAS) | {"build"} <= read
    assert read <= set(_outputs())


def test_the_partitions_are_one_or_two() -> None:
    heavy = changes().HEAVY_CRATES
    for crate in MEMBERS:
        partitions = json.loads(
            changes().Plan(mode="pr", crates={crate}).outputs(MEMBERS)["partitions"]
        )
        assert partitions == ([1, 2] if crate in heavy else [1]), crate
    # The real heavy crates exist.
    assert heavy <= set(CRATES) | {"opentide-lsp"}


def test_main_writes_the_outputs_and_a_summary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = changes()
    output = tmp_path / "output"
    summary = tmp_path / "summary"
    monkeypatch.setattr(module, "cargo_metadata", _metadata)
    monkeypatch.setattr(module, "changed_paths", lambda base, head: ["grammars/kql/grammar.js"])
    for name, value in {
        **PULL,
        "GITHUB_OUTPUT": str(output),
        "GITHUB_STEP_SUMMARY": str(summary),
    }.items():
        monkeypatch.setenv(name, value)
    assert module.main([]) == 0
    written = dict(line.split("=", 1) for line in output.read_text("utf-8").splitlines())
    assert written["grammars"] == "true" and written["docs"] == "false"
    assert written["mode"] == "pr"
    assert "grammars/kql/grammar.js: grammars/*" in summary.read_text("utf-8")
