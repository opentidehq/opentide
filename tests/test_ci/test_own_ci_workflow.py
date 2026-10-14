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
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

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
