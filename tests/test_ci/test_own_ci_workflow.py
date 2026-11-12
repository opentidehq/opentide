"""Contract for ``ci.yml``: the E2E shards must cover every test, once.

The E2E suite is split across runners with ``pytest-split``
(``--splits N --group K``). ``--splits`` partitions the whole selection, so no
test can fall outside a group -- but only the groups that have a matrix entry
actually run. If the matrix list and ``--splits`` ever disagree, the tests in
the groups above the matrix length are skipped with no failure and no warning,
which is the one way this speed-up could silently cost coverage.

Also pins the concurrency of the long jobs. ``cli-e2e`` used to declare
``needs: [test]``, which put the slowest unit cell (~344 s) in front of the
longest job in the workflow (~980 s) for a ~22 min wall clock. They share no
artifact, so the dependency bought nothing; restoring it would quietly undo
most of the win.

Also covers the vocabulary drift gate's path filter. It used ``rg``, which
GitHub-hosted runners do not ship; inside ``if`` the missing command read as
"no match", so the drift check never ran. The check is
``cargo xtask vocab sync --check`` (``xtask/src/vocab/sync.rs``). When the gate fires,
``--check`` must see a specifications checkout: without one it only compares the
lockfile with the bundle, and hand-edited pins pass once relocked.

The same checkout feeds the model field description check, which must fail
rather than skip when the checkout is missing.

Also holds the engine crates' licence scan to what the package step leaves
out: a workspace crate under ``crates/`` excluded from ``cargo package`` is not
published (``publish = false``), and the scan reads its source directory
instead, so an exclusion never quietly shrinks the scan.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
SHARDED_JOB = "cli-e2e"
# Jobs that must not be gated on the unit matrix: they consume nothing it
# produces, and waiting for it is pure wall clock.
CONCURRENT_JOBS = ("cli-e2e", "cli-windows-smoke", "gitlab-ci-lint")


@pytest.fixture(scope="module")
def workflow() -> dict[str, Any]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _e2e_pytest_step(workflow: dict[str, Any]) -> str:
    """The ``run`` body of the sharded pytest step."""
    steps = workflow["jobs"][SHARDED_JOB]["steps"]
    runs = [str(step.get("run", "")) for step in steps]
    sharded = [run for run in runs if "--splits" in run]
    assert len(sharded) == 1, (
        f"expected exactly one --splits step in {SHARDED_JOB}, found {len(sharded)}"
    )
    return sharded[0]


def test_shard_matrix_covers_every_split(workflow: dict[str, Any]) -> None:
    """Matrix entries and ``--splits`` must agree, or tests vanish silently."""
    shards = workflow["jobs"][SHARDED_JOB]["strategy"]["matrix"]["shard"]
    run = _e2e_pytest_step(workflow)

    match = re.search(r"--splits\s+(\d+)", run)
    assert match is not None, f"no --splits in the {SHARDED_JOB} pytest step"
    splits = int(match.group(1))

    assert sorted(shards) == list(range(1, splits + 1)), (
        f"{SHARDED_JOB} runs --splits {splits} but its matrix is {shards}. "
        f"pytest-split assigns every selected test to a group in 1..{splits}; "
        f"groups without a matrix entry are never run and report no failure. "
        f"Set the matrix to {list(range(1, splits + 1))} or change --splits to match."
    )


def test_shard_group_is_driven_by_the_matrix(workflow: dict[str, Any]) -> None:
    """``--group`` must read the matrix, not a constant."""
    run = _e2e_pytest_step(workflow)
    assert "--group ${{ matrix.shard }}" in run, (
        f"{SHARDED_JOB} must pass --group ${{{{ matrix.shard }}}}; a constant group "
        f"would run the same subset on every runner and skip the rest."
    )


def test_durations_file_is_present(workflow: dict[str, Any]) -> None:
    """A missing durations file degrades balance to an even test-count split."""
    run = _e2e_pytest_step(workflow)
    match = re.search(r"--durations-path\s+(\S+)", run)
    assert match is not None, "the sharded step should pin an explicit --durations-path"
    path = ROOT / match.group(1)
    assert path.is_file(), (
        f"{path.name} is referenced by ci.yml but missing. Without it pytest-split "
        f"falls back to an even split by test count, and the heavy E2E tests cluster "
        f"into one shard. Refresh it with scripts/ci-local.sh --store-e2e-durations."
    )


@pytest.mark.parametrize("job", CONCURRENT_JOBS)
def test_long_jobs_do_not_wait_for_the_unit_matrix(workflow: dict[str, Any], job: str) -> None:
    """These jobs must stay off the unit matrix's critical path."""
    needs = workflow["jobs"][job].get("needs") or []
    needs = [needs] if isinstance(needs, str) else list(needs)
    assert "test" not in needs, (
        f"{job} declares needs: [test], which serialises it behind the slowest "
        f"unit cell (~344 s) for no shared artifact. That dependency is what made "
        f"the workflow ~22 min; the jobs are independent and must run concurrently."
    )


def test_sysmon_coverage_cell_is_new_enough(workflow: dict[str, Any]) -> None:
    """``COVERAGE_CORE=sysmon`` needs 3.12+, so the coverage cell must be 3.12+.

    The coverage step halves its own runtime by using PEP 669 ``sys.monitoring``
    instead of the C trace function. That backend does not exist before 3.12, so
    lowering COVERAGE_PYTHON would silently fall back to the slow tracer -- or
    error -- with nothing in the workflow to say why.
    """
    steps = workflow["jobs"]["test"]["steps"]
    sysmon = [s for s in steps if (s.get("env") or {}).get("COVERAGE_CORE") == "sysmon"]
    if not sysmon:
        pytest.skip("no step requests the sys.monitoring coverage backend")

    raw = str(workflow["env"]["COVERAGE_PYTHON"])
    version = tuple(int(part) for part in raw.split("."))
    assert version >= (3, 12), (
        f"COVERAGE_PYTHON is {raw}, but a step sets COVERAGE_CORE=sysmon and "
        f"sys.monitoring (PEP 669) only exists on 3.12+. Either raise "
        f"COVERAGE_PYTHON back to 3.12 or newer, or drop the COVERAGE_CORE env."
    )


def _vocab_gate_pattern(workflow: dict[str, Any]) -> str:
    """The ERE the ``vocab_changes`` step greps changed paths with."""
    steps = workflow["jobs"]["lint"]["steps"]
    runs = [str(step.get("run", "")) for step in steps if step.get("id") == "vocab_changes"]
    assert len(runs) == 1, "expected exactly one vocab_changes step in the lint job"
    match = re.search(r'grep -qE "([^"]+)"', runs[0])
    assert match is not None, "vocab_changes must filter paths with grep -qE (rg is not installed)"
    # Bash double quotes turn the workflow's ``\\.`` into ``\.``.
    return match.group(1).replace("\\\\", "\\")


@pytest.mark.parametrize(
    ("path", "gated"),
    [
        ("src/opentide/data/vocabulary/att&ck.vocab.toml", True),
        ("src/opentide/data/pins/threat.toml", True),
        ("data/specifications.lock.json", True),
        ("xtask/src/vocab/sync.rs", True),
        ("src/opentide/_models/vocab_pins.py", False),
    ],
)
def test_vocab_drift_gate_watches_bundle_pins_and_lockfile(
    workflow: dict[str, Any], path: str, gated: bool
) -> None:
    assert bool(re.search(_vocab_gate_pattern(workflow), path)) is gated


def test_vocab_drift_check_compares_against_a_specifications_checkout(
    workflow: dict[str, Any],
) -> None:
    steps = workflow["jobs"]["lint"]["steps"]
    checks = [
        step for step in steps if "cargo xtask vocab sync --check" in str(step.get("run", ""))
    ]
    assert len(checks) == 1, "expected exactly one `cargo xtask vocab sync --check` step in lint"
    root = checks[0].get("env", {}).get("OPENTIDE_SPECIFICATIONS_ROOT", "")
    assert root == "${{ github.workspace }}/specifications"

    checkouts = [
        step
        for step in steps[: steps.index(checks[0])]
        if step.get("with", {}).get("repository") == "opentidehq/specifications"
    ]
    assert len(checkouts) == 1, "the drift check needs a specifications checkout before it"
    assert checkouts[0]["with"]["path"] == "specifications"
    assert checkouts[0]["with"].get("ref") == "main"
    # Gated on (at least) the check's condition, so the check never runs
    # without the clone.
    assert checks[0].get("if") in _conditions(checkouts[0])


def _conditions(step: dict[str, Any]) -> list[str]:
    """The ``||`` alternatives of a step's ``if``."""
    return [part.strip() for part in str(step.get("if", "")).split("||")]


def _field_gate_pattern(workflow: dict[str, Any]) -> str:
    """The ERE that sets ``fields=true`` in the ``vocab_changes`` step."""
    steps = workflow["jobs"]["lint"]["steps"]
    run = next(str(step["run"]) for step in steps if step.get("id") == "vocab_changes")
    match = re.search(r'grep -qE "([^"]+)"[^\n]*\n\s*echo "fields=true"', run)
    assert match is not None, "vocab_changes must set fields=true from a grep -qE path filter"
    return match.group(1).replace("\\\\", "\\")


@pytest.mark.parametrize(
    ("path", "gated"),
    [
        ("src/opentide/_models/platform.py", True),
        ("src/opentide/_models/platform_configs.py", True),
        ("tests/test_models/test_spec_field_descriptions.py", True),
        (".github/workflows/ci.yml", True),
        ("src/opentide/generation/schema_pipeline.py", False),
        ("tests/test_models/test_platform.py", False),
    ],
)
def test_field_description_gate_watches_models_and_the_test(
    workflow: dict[str, Any], path: str, gated: bool
) -> None:
    assert bool(re.search(_field_gate_pattern(workflow), path)) is gated


def test_field_description_check_requires_a_specifications_checkout(
    workflow: dict[str, Any],
) -> None:
    steps = workflow["jobs"]["lint"]["steps"]
    checks = [
        step
        for step in steps
        if "tests/test_models/test_spec_field_descriptions.py" in str(step.get("run", ""))
    ]
    assert len(checks) == 1, "expected exactly one spec field description step in lint"
    env = checks[0].get("env", {})
    assert env.get("OPENTIDE_SPECIFICATIONS_ROOT") == "${{ github.workspace }}/specifications"
    # Without it the test skips when the checkout is missing, and the guard is off.
    assert str(env.get("OPENTIDE_REQUIRE_SPECIFICATIONS")) == "1"
    checkouts = [
        step
        for step in steps[: steps.index(checks[0])]
        if step.get("with", {}).get("repository") == "opentidehq/specifications"
    ]
    assert len(checkouts) == 1
    assert checks[0].get("if") in _conditions(checkouts[0])


LOCAL_CI = ROOT / "scripts" / "ci-local.sh"


def _package_and_scan(text: str) -> tuple[set[str], str]:
    """The crates a ``cargo package`` command excludes, and the licence scan commands."""
    # `cargo package --list` only names a crate's files (for the scan of a
    # crate that cannot be packaged); it packages nothing.
    packages = [
        line
        for line in text.splitlines()
        if "cargo package" in line and "cargo package --list" not in line
    ]
    scans = [line for line in text.splitlines() if "license-scan.sh" in line and "bash" in line]
    assert len(packages) == 1, packages
    assert scans, text
    return set(re.findall(r"--exclude\s+(\S+)", packages[0])), " ".join(scans)


def _engine_package_text(workflow: dict[str, Any]) -> str:
    steps = workflow["jobs"]["engine-package"]["steps"]
    return "\n".join(str(step.get("run", "")) for step in steps)


def _workspace_crates(root: Path = ROOT) -> dict[str, Path]:
    """Each workspace crate's package name and its directory, relative to *root*.

    The crates under ``crates/`` and the language bindings under ``bindings/``
    (``opentide-node``, UC-5.3a): ``cargo package --workspace`` reaches both.
    """
    crates: dict[str, Path] = {}
    for manifest_path in sorted(
        [*root.glob("crates/*/Cargo.toml"), *root.glob("bindings/*/Cargo.toml")]
    ):
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        name = manifest.get("package", {}).get("name", manifest_path.parent.name)
        crates[name] = manifest_path.parent.relative_to(root)
    return crates


def _check_excluded_crates_are_scanned(text: str, root: Path = ROOT) -> None:
    excluded, scan = _package_and_scan(text)
    crates = _workspace_crates(root)
    for name in sorted(excluded):
        if name not in crates:
            continue
        directory = crates[name].as_posix()
        manifest = (root / directory / "Cargo.toml").read_text(encoding="utf-8")
        assert re.search(r"^publish\s*=\s*false\s*$", manifest, re.MULTILINE), (
            f"{name} is left out of `cargo package` but is published: package it, "
            "and drop the --exclude, before it is released"
        )
        assert directory in scan.split(), (
            f"{name} is left out of `cargo package`: the licence scan must read {directory}"
        )


_DEPENDENCY_SECTIONS = ("dependencies", "build-dependencies")


def _check_packaged_crates_avoid_excluded(text: str, root: Path = ROOT) -> None:
    """A crate ``cargo package`` packages cannot depend on one it leaves out.

    The left-out crates are unpublished, so the packaged crate's dependency on
    one resolves against crates.io and the whole step fails (opentide-connectors
    on opentide-workspace, UC-4.1).
    """
    excluded, _ = _package_and_scan(text)
    for name, directory in _workspace_crates(root).items():
        manifest = tomllib.loads((root / directory / "Cargo.toml").read_text(encoding="utf-8"))
        if name in excluded:
            continue
        for section in _DEPENDENCY_SECTIONS:
            for dependency in manifest.get(section, {}):
                assert dependency not in excluded, (
                    f"{name} is packaged but its {section} name {dependency}, which "
                    f"`cargo package` leaves out: exclude {name} too and scan its sources"
                )


def test_engine_package_scans_the_crates_it_does_not_package(workflow: dict[str, Any]) -> None:
    text = _engine_package_text(workflow)
    # The test harnesses are never published; the facade and its crates are.
    assert "opentide-compare" in _package_and_scan(text)[0]
    assert "opentide" not in _package_and_scan(text)[0]
    _check_excluded_crates_are_scanned(text)
    _check_packaged_crates_avoid_excluded(text)


def test_local_ci_scans_the_crates_it_does_not_package() -> None:
    text = LOCAL_CI.read_text(encoding="utf-8")
    # The test harnesses are never published; the facade and its crates are.
    assert "opentide-compare" in _package_and_scan(text)[0]
    assert "opentide" not in _package_and_scan(text)[0]
    _check_excluded_crates_are_scanned(text)
    _check_packaged_crates_avoid_excluded(text)


def test_the_dependency_check_fails_for_a_packaged_crate_on_an_excluded_one(
    tmp_path: Path,
) -> None:
    crate = tmp_path / "crates" / "opentide-connectors"
    crate.mkdir(parents=True)
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "opentide-connectors"\npublish = false\n'
        "[dependencies]\nopentide-schema.workspace = true\n"
        "[dev-dependencies]\nopentide-cassette.workspace = true\n",
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="opentide-connectors is packaged"):
        _check_packaged_crates_avoid_excluded(_EXCLUDED_SCANNED, tmp_path)
    excluded_too = _EXCLUDED_SCANNED.replace(
        "--exclude opentide-schema", "--exclude opentide-schema --exclude opentide-connectors"
    )
    _check_packaged_crates_avoid_excluded(excluded_too, tmp_path)


def test_the_dependency_check_reads_the_bindings_too(tmp_path: Path) -> None:
    # opentide-node (bindings/node, UC-5.3a) depends on the opentide facade,
    # which the package step leaves out: packaging it failed the step.
    crate = tmp_path / "bindings" / "node"
    crate.mkdir(parents=True)
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "opentide-node"\npublish = false\n'
        '[dependencies]\nopentide = { path = "../../crates/opentide" }\n',
        encoding="utf-8",
    )
    text = "cargo package --workspace --exclude opentide\nbash scripts/engine/license-scan.sh x\n"
    with pytest.raises(AssertionError, match="opentide-node is packaged"):
        _check_packaged_crates_avoid_excluded(text, tmp_path)
    excluded_too = text.replace(
        "--exclude opentide\n", "--exclude opentide --exclude opentide-node\n"
    )
    with pytest.raises(AssertionError, match="licence scan must read bindings/node"):
        _check_excluded_crates_are_scanned(excluded_too, tmp_path)
    _check_excluded_crates_are_scanned(excluded_too.replace(" x\n", " bindings/node\n"), tmp_path)


_EXCLUDED_UNSCANNED = (
    "cargo package --workspace --exclude opentide-compare\n"
    "bash scripts/engine/license-scan.sh target/package/*.crate\n"
)
_EXCLUDED_SCANNED = (
    "cargo package --workspace --exclude opentide-schema\n"
    "bash scripts/engine/license-scan.sh target/package/*.crate crates/opentide-schema\n"
)


def test_the_scan_check_fails_for_an_excluded_crate_it_does_not_scan() -> None:
    with pytest.raises(AssertionError, match="licence scan must read crates/opentide-compare"):
        _check_excluded_crates_are_scanned(_EXCLUDED_UNSCANNED)


def test_the_published_crates_are_packaged_not_excluded() -> None:
    """The release train publishes opentide-schema: leaving it out of the
    package step would ship a crate CI never built from its package."""
    with pytest.raises(AssertionError, match="opentide-schema is left out of `cargo package`"):
        _check_excluded_crates_are_scanned(_EXCLUDED_SCANNED)


@pytest.mark.parametrize("publish", ["", 'publish = ["crates-io"]\n'])
def test_the_scan_check_fails_once_an_excluded_crate_is_published(
    tmp_path: Path, publish: str
) -> None:
    # opentide-schema losing `publish = false` while the package step still
    # excludes it: the exclusion must go, so the crate is packaged and scanned.
    crate = tmp_path / "crates" / "opentide-schema"
    crate.mkdir(parents=True)
    (crate / "Cargo.toml").write_text(
        f'[package]\nname = "opentide-schema"\n{publish}', encoding="utf-8"
    )
    with pytest.raises(AssertionError, match="is left out of `cargo package` but is published"):
        _check_excluded_crates_are_scanned(_EXCLUDED_SCANNED, tmp_path)
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "opentide-schema"\npublish = false\n', encoding="utf-8"
    )
    _check_excluded_crates_are_scanned(_EXCLUDED_SCANNED, tmp_path)


def _corpus_step(workflow: dict[str, Any], needle: str) -> dict[str, Any]:
    steps = workflow["jobs"]["corpus"]["steps"]
    found = [step for step in steps if needle in str(step.get("run", ""))]
    assert len(found) == 1, f"expected exactly one corpus step running {needle!r}"
    return found[0]


def _vocab_resolution_pattern(workflow: dict[str, Any]) -> str:
    """The ERE the corpus job's ``vocab_resolution`` step greps changed paths with."""
    steps = workflow["jobs"]["corpus"]["steps"]
    runs = [str(step.get("run", "")) for step in steps if step.get("id") == "vocab_resolution"]
    assert len(runs) == 1, "expected exactly one vocab_resolution step in the corpus job"
    match = re.search(r'grep -qE "([^"]+)"', runs[0])
    assert match is not None, "vocab_resolution must filter paths with grep -qE (no rg)"
    return match.group(1).replace("\\\\", "\\")


@pytest.mark.parametrize(
    ("path", "gated"),
    [
        ("crates/opentide-core/src/suggest.rs", True),
        ("crates/opentide-schema/src/vocab/mod.rs", True),
        ("crates/opentide-schema/src/vocab/sentinel.rs", True),
        ("src/opentide/data/vocabulary/tlp.vocab.toml", True),
        ("src/opentide/data/pins/rule.toml", True),
        ("tests/corpora/fault/catalogue.toml", True),
        ("tests/golden/vocab/APPROVED.toml", True),
        ("tests/golden/cases.toml", True),
        ("xtask/src/vocab/diff.rs", True),
        ("xtask/src/vocab/probe.py", True),
        (".github/workflows/ci.yml", True),
        ("crates/opentide-core/src/suggests.rs", False),
        ("crates/opentide-schema/src/pins.rs", False),
        ("xtask/src/vocab/sync.rs", False),
    ],
)
def test_vocab_diff_gate_watches_resolution_data_and_approvals(
    workflow: dict[str, Any], path: str, gated: bool
) -> None:
    assert bool(re.search(_vocab_resolution_pattern(workflow), path)) is gated


def test_vocab_diff_runs_against_the_installed_oracle(workflow: dict[str, Any]) -> None:
    """``cargo xtask vocab diff --against python`` enforces APPROVED.toml (UC-1.6)."""
    steps = workflow["jobs"]["corpus"]["steps"]
    diff = _corpus_step(workflow, "cargo xtask vocab diff --against python")
    assert diff.get("if") == "steps.vocab_resolution.outputs.changed == 'true'"
    assert '--python "$RUNNER_TEMP/oracle/bin/python"' in str(diff["run"])
    oracle = _corpus_step(workflow, "oracle-requirements.txt")
    assert steps.index(oracle) < steps.index(diff), "the oracle is installed before the diff"
    # The filter diffs against the base commit, so the checkout keeps history.
    assert steps[0]["with"].get("fetch-depth") == 0
