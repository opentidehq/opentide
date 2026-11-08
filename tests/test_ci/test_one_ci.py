"""One CI for the repository (#801), and the release workflows' triggers.

``ci.yml`` checks the whole repository on every pull request and push: the
Python jobs, and the Cargo workspace's (rustfmt, clippy, nextest on three
operating systems, rustdoc, WebAssembly, grammars, npm packs, the licence scan,
a fuzz smoke run of every target, and a dry run of the engine release). The
checks branch protection requires are the list ``.github/AGENTS.md`` gives.

Releases: ``v*`` tags are opentide's (publish-pypi.yml); the engine releases
from ``engine-v*`` tags (engine-release.yml). No other workflow may run on a
``v*`` tag, and nothing publishes from a trigger that is not a release.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
CI = WORKFLOWS / "ci.yml"
GUIDE = ROOT / ".github" / "AGENTS.md"

# What publishes a package, a release or a signed statement about one.
PUBLISHING = re.compile(
    r"cargo publish|release\.py publish|npm publish|gh release (?:create|upload)"
    r"|pypa/gh-action-pypi-publish|actions/attest-build-provenance|crates-io-auth-action"
)
PUBLISHERS = {"publish-pypi.yml", "engine-release.yml"}
# Triggers a release may start from: a tag, a GitHub Release, or a person.
RELEASE_TRIGGERS = {"push", "release", "workflow_dispatch", "repository_dispatch"}
# Expressions an outsider controls: never interpolated into a shell.
UNTRUSTED = re.compile(r"\$\{\{[^}]*(github\.event\.|github\.head_ref|inputs\.)[^}]*\}\}")
SHA_PIN = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
# The workflows this item owns hold every checkout to persist-credentials: false.
NO_CREDENTIALS = [
    "ci.yml",
    "codeql.yml",
    "engine-release.yml",
    "engine-release-build.yml",
    "engine-fuzz.yml",
    "oracle.yml",
]


def _load(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _triggers(workflow: dict[str, Any]) -> dict[str, Any]:
    # PyYAML reads the key `on` as True.
    on = workflow.get("on", workflow.get(True))
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return dict.fromkeys(on)
    return dict(on or {})


def _workflows() -> list[Path]:
    return sorted(WORKFLOWS.glob("*.yml"))


def _runs_on_tag(triggers: dict[str, Any], tag: str) -> bool:
    """Whether a push of `tag`, or a GitHub Release for it, starts the workflow."""
    if "release" in triggers or "create" in triggers:
        return True
    if "push" not in triggers:
        return False
    push = triggers["push"] or {}
    tags = push.get("tags")
    ignored = push.get("tags-ignore")
    if tags is None and ignored is None:
        # A branch filter alone runs on no tag; no filter runs on every tag.
        return "branches" not in push and "branches-ignore" not in push
    if tags is not None:
        return any(fnmatch.fnmatchcase(tag, pattern) for pattern in tags)
    return not any(fnmatch.fnmatchcase(tag, pattern) for pattern in ignored)


@pytest.mark.parametrize("tag", ["v0.24.0", "v1.0.0-rc.1", "v10.2.3"])
def test_only_publish_pypi_runs_on_an_opentide_tag(tag: str) -> None:
    starting = sorted(
        path.name for path in _workflows() if _runs_on_tag(_triggers(_load(path)), tag)
    )
    assert starting == ["publish-pypi.yml"], starting


def test_the_tag_check_reads_triggers() -> None:
    assert _runs_on_tag({"push": {"tags": ["v*"]}}, "v1.0.0")
    assert _runs_on_tag({"push": None}, "v1.0.0")
    assert _runs_on_tag({"release": {"types": ["published"]}}, "v1.0.0")
    assert not _runs_on_tag({"push": {"branches": ["development"]}}, "v1.0.0")
    assert not _runs_on_tag({"push": {"tags": ["engine-v*"]}}, "v1.0.0")
    assert _runs_on_tag({"push": {"tags-ignore": ["engine-v*"]}}, "v1.0.0")


def test_the_engine_releases_from_engine_tags_and_run_workflow_only() -> None:
    triggers = _triggers(_load(WORKFLOWS / "engine-release.yml"))
    assert set(triggers) == {"push", "workflow_dispatch"}
    assert triggers["push"] == {"tags": ["engine-v*"]}
    for tag in ["engine-v0.11.0", "engine-v0.11.1-rc.1"]:
        assert _runs_on_tag(triggers, tag)


def test_nothing_publishes_from_a_trigger_that_is_not_a_release() -> None:
    publishing = sorted(
        path.name for path in _workflows() if PUBLISHING.search(path.read_text(encoding="utf-8"))
    )
    assert publishing == sorted(PUBLISHERS)
    for name in PUBLISHERS:
        triggers = _triggers(_load(WORKFLOWS / name))
        assert set(triggers) <= RELEASE_TRIGGERS, (name, sorted(triggers))
        push = triggers.get("push") or {}
        # A push publishes only for a tag, never a branch.
        assert "push" not in triggers or set(push) == {"tags"}, (name, push)


def test_the_asset_build_publishes_nothing_and_writes_nothing() -> None:
    path = WORKFLOWS / "engine-release-build.yml"
    workflow = _load(path)
    assert set(_triggers(workflow)) == {"workflow_call"}
    assert workflow["permissions"] == {"contents": "read"}
    for job_id, job in workflow["jobs"].items():
        assert job.get("permissions") in (None, {"contents": "read"}), job_id
    assert not PUBLISHING.search(path.read_text(encoding="utf-8"))
    assert "id-token" not in path.read_text(encoding="utf-8")


def test_the_pull_request_dry_run_is_read_only() -> None:
    job = _load(CI)["jobs"]["engine-release-dry-run"]
    assert job["uses"] == "./.github/workflows/engine-release-build.yml"
    assert job["with"] == {"dry-run": True}
    assert job["permissions"] == {"contents": "read"}
    release = _load(WORKFLOWS / "engine-release.yml")["jobs"]["build"]
    assert release["uses"] == job["uses"]
    assert "dry-run" not in (release.get("with") or {})


@pytest.mark.parametrize("path", _workflows(), ids=lambda path: path.name)
def test_every_action_is_pinned_by_commit(path: Path) -> None:
    for job_id, job in _load(path)["jobs"].items():
        uses = [job["uses"]] if "uses" in job else []
        uses += [str(step["uses"]) for step in job.get("steps") or [] if "uses" in step]
        for ref in uses:
            if ref.startswith("./"):
                continue
            assert SHA_PIN.match(ref), f"{path.name} {job_id}: {ref} is not pinned by commit"


@pytest.mark.parametrize("path", _workflows(), ids=lambda path: path.name)
def test_no_untrusted_expression_in_a_shell(path: Path) -> None:
    for job_id, job in _load(path)["jobs"].items():
        for step in job.get("steps") or []:
            found = UNTRUSTED.search(str(step.get("run", "")))
            assert found is None, f"{path.name} {job_id}: pass {found.group(0)} through env"


@pytest.mark.parametrize("name", NO_CREDENTIALS)
def test_checkouts_keep_no_credentials(name: str) -> None:
    for job_id, job in _load(WORKFLOWS / name)["jobs"].items():
        for step in job.get("steps") or []:
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert (step.get("with") or {}).get("persist-credentials") is False, (
                    f"{name} {job_id}"
                )


def _step_runs(job: dict[str, Any]) -> str:
    return "\n".join(str(step.get("run", "")) for step in job.get("steps") or [])


def _ci_jobs() -> dict[str, Any]:
    return _load(CI)["jobs"]


def test_ci_runs_on_every_pull_request_and_on_development() -> None:
    triggers = _triggers(_load(CI))
    assert triggers["pull_request"] is None, "every base branch, no path filter"
    assert "development" in triggers["push"]["branches"]


@pytest.mark.parametrize(
    ("job", "command"),
    [
        ("engine", "cargo fmt --all --check"),
        ("engine", "cargo clippy --workspace --all-targets --locked -- -D warnings"),
        ("engine", "cargo xtask check-layers"),
        ("engine", "cargo doc --no-deps --workspace --locked"),
        ("engine-test", "cargo nextest run --workspace --locked --profile ci"),
        ("engine-test", "cargo test --workspace --locked --doc"),
        ("engine-wasm", "bash scripts/engine/build-wasm.sh"),
        ("engine-wasm", "node scripts/engine/check-npm-packs.mjs"),
        ("engine-package", "bash scripts/engine/license-scan.sh target/package/*.crate"),
        ("grammars", "bash scripts/engine/check-grammars.sh"),
        ("fuzz-smoke", 'bash scripts/engine/fuzz.sh "${target}" 60'),
        ("engine-release-consumers", "node scripts/engine/check-vscode-extension.mjs"),
    ],
)
def test_ci_runs_the_rust_gates(job: str, command: str) -> None:
    assert command in _step_runs(_ci_jobs()[job])


def test_rustdoc_denies_warnings() -> None:
    steps = _ci_jobs()["engine"]["steps"]
    doc = next(step for step in steps if "cargo doc" in str(step.get("run", "")))
    assert doc["env"]["RUSTDOCFLAGS"] == "-D warnings"


def test_nextest_runs_on_three_operating_systems() -> None:
    matrix = _ci_jobs()["engine-test"]["strategy"]["matrix"]
    assert matrix["os"] == ["ubuntu-latest", "macos-latest", "windows-latest"]


def test_the_fuzz_smoke_covers_every_target() -> None:
    targets = sorted(path.stem for path in (ROOT / "fuzz" / "fuzz_targets").glob("*.rs"))
    assert targets
    groups = _ci_jobs()["fuzz-smoke"]["strategy"]["matrix"]["targets"]
    listed = sorted(target for group in groups for target in group.split())
    assert listed == targets


def test_language_servers_engine_ci_is_folded_in() -> None:
    assert not (WORKFLOWS / "engine-ci.yml").exists()
    assert not (ROOT / ".github" / "engine-workflows").exists()


def _check_names(path: Path) -> list[tuple[str, bool]]:
    """Each check run a pull request gets from the workflow, with whether it
    can fail the pull request (a job with continue-on-error cannot)."""
    workflow = _load(path)
    names: list[tuple[str, bool]] = []
    for job_id, job in workflow["jobs"].items():
        name = str(job.get("name", job_id))
        gating = job.get("continue-on-error") is not True
        if "uses" in job:
            called = _load(ROOT / job["uses"].removeprefix("./"))
            names += [(f"{name} / {sub}", gating) for sub, _ in _check_names_of(called)]
            continue
        names += [(cell, gating) for cell in _expand(name, job)]
    return names


def _check_names_of(workflow: dict[str, Any]) -> list[tuple[str, bool]]:
    return [
        (cell, job.get("continue-on-error") is not True)
        for job_id, job in workflow["jobs"].items()
        for cell in _expand(str(job.get("name", job_id)), job)
    ]


def _expand(name: str, job: dict[str, Any]) -> list[str]:
    matrix = (job.get("strategy") or {}).get("matrix") or {}
    axes = {k: v for k, v in matrix.items() if k not in ("include", "exclude")}
    cells: list[dict[str, str]] = [{}]
    for axis, values in axes.items():
        cells = [{**cell, axis: str(value)} for cell in cells for value in values]
    if not axes and matrix.get("include"):
        cells = [{str(k): str(v) for k, v in entry.items()} for entry in matrix["include"]]
    pattern = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}")
    return [pattern.sub(lambda m, cell=cell: cell[m.group(1)], name) for cell in cells]


def _documented_checks() -> list[str]:
    text = GUIDE.read_text(encoding="utf-8")
    block = re.search(r"<!-- required-checks -->\n```text\n(.*?)```", text, re.DOTALL)
    assert block is not None, ".github/AGENTS.md lists the required checks"
    return block.group(1).splitlines()


def test_the_required_checks_are_every_gating_check() -> None:
    expected = [
        name
        for path in (CI, WORKFLOWS / "codeql.yml")
        for name, gating in _check_names(path)
        if gating
    ]
    assert len(expected) == len(set(expected)), "check names are unique"
    assert sorted(_documented_checks()) == sorted(expected)


def test_the_informational_jobs_are_not_required() -> None:
    informational = [name for name, gating in _check_names(CI) if not gating]
    assert sorted(informational) == ["Benchmarks (informational)", "LSP clients (informational)"]
    for name in informational:
        assert name not in _documented_checks()
