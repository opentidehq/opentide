"""golden.yml starts on every pull request into integration/unified-core (#803).

Branch protection on ``integration/unified-core`` requires two of golden.yml's
checks (the second list in ``.github/AGENTS.md``). A required check that never
starts blocks the merge, so the ``pull_request`` trigger takes no path or
branch filter: the ``changes`` job (``Golden paths``) filters by path inside
the workflow, and a job its ``if`` skips reports success.

- ``Golden check (python)`` runs on a pull request when a golden input changed,
  with the ``full-ci`` label, and when the filter did not succeed. Since UC-6.2
  (#841) its oracle is a frozen PyPI release, so a pull request that touches
  none of its inputs cannot change its result (the maintainer's decision).
- ``Golden determinism`` records every case twice (about 26 minutes): it is in
  ci.yml's full set, so on a pull request it runs only with the ``full-ci``
  label, and it is not required.
- Both run on every push, the nightly schedule and Run workflow.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / ".github" / "workflows" / "golden.yml"
GUIDE = ROOT / ".github" / "AGENTS.md"
INTEGRATION = "integration/unified-core"

# The jobs, by id: renaming a required one breaks the rule.
JOB_NAMES = {
    "changes": "Golden paths",
    "check": "Golden check (python)",
    "determinism": "Golden determinism",
}
# The ones integration/unified-core requires: they start on every pull request
# into it (a job its `if` skips counts as passing).
REQUIRED = ["changes", "check"]
FULL_CI = "full-ci"

# The check's inputs, as bash patterns: the cases and recordings, the inputs
# the cases read, the renderers' oracle snapshots and their driver (UC-3.4,
# #826), and the code that runs the oracle and compares its output.
GOLDEN_PATHS = [
    "tests/golden/*",
    "tests/fixtures/tide_corpus/*",
    "scripts/golden/*",
    "crates/opentide-cli/tests/render/*",
    "tests/corpora/*",
    "xtask/src/golden/*",
    "xtask/src/corpus/*",
    "xtask/src/compare.rs",
    "xtask/src/parallel.rs",
    "crates/opentide-compare/*",
    ".github/workflows/golden.yml",
]


def _workflow() -> dict[str, Any]:
    return yaml.safe_load(GOLDEN.read_text(encoding="utf-8"))


def _triggers() -> dict[str, Any]:
    workflow = _workflow()
    # PyYAML reads the key `on` as True.
    return workflow.get("on", workflow.get(True))


def _paths_step() -> dict[str, Any]:
    steps = _workflow()["jobs"]["changes"]["steps"]
    return next(step for step in steps if step.get("id") == "paths")


# GitHub's status-check functions, for one run that was not cancelled and
# whose only dependency is `changes`.
STATUS = re.compile(r"(!\s*)?\b(success|failure|always|cancelled)\(\)")
# Whether the pull request carries a label: the one call to `contains` the
# workflows make. `labels` in the context is the comma-separated label names.
LABELLED = re.compile(r"contains\(github\.event\.pull_request\.labels\.\*\.name,\s*'([^']+)'\)")


def _evaluate(condition: str, context: dict[str, str]) -> bool:
    """Evaluate a job's `if` for one event: the subset of GitHub's expression
    language golden.yml and ci.yml use (status functions, `!`, `&&`, `||`,
    `==`, `!=`, and `contains` on the pull request's label names).

    As on GitHub, a condition with no status function gets an implicit
    `success()`: the job is skipped when a job it needs did not succeed."""
    if not STATUS.search(condition):
        condition = f"success() && ({condition})"
    labels = [label for label in context.get("labels", "").split(",") if label]
    condition = LABELLED.sub(lambda m: repr(m.group(1) in labels), condition)
    result = context["needs.changes.result"]
    status = {
        "success": result == "success",
        "failure": result == "failure",
        "always": True,
        "cancelled": False,
    }

    def call(match: re.Match[str]) -> str:
        value = status[match.group(2)]
        return repr(not value if match.group(1) else value)

    expression = STATUS.sub(call, condition)
    expression = expression.replace("&&", " and ").replace("||", " or ")
    names = re.compile(r"\b(?:github|needs)\.[A-Za-z0-9_.*]+")
    unknown = {name for name in names.findall(expression) if name not in context}
    assert not unknown, f"the test does not know {unknown}"
    expression = names.sub(lambda m: repr(context[m.group(0)]), expression)
    # Only literals, names and operators are left: the workflow's own text.
    assert re.fullmatch(r"[\sA-Za-z0-9_'()/=!.-]*", expression), expression
    return bool(eval(expression, {"__builtins__": {}}))


def _context(event: str, base: str, result: str, golden: str, labels: str = "") -> dict[str, str]:
    return {
        "github.event_name": event,
        "github.base_ref": base,
        "needs.changes.result": result,
        "needs.changes.outputs.golden": golden,
        "labels": labels,
    }


def test_the_pull_request_trigger_has_no_filter() -> None:
    # A path filter back on the trigger means a required check that never
    # starts on most pull requests into integration/unified-core.
    pull_request = _triggers()["pull_request"] or {}
    assert pull_request == {}, f"golden.yml's pull_request trigger is filtered: {pull_request}"


def test_push_and_the_nightly_schedule() -> None:
    triggers = _triggers()
    assert triggers["push"] == {"branches": ["development", INTEGRATION, "train/catchup-*"]}
    # Nightly: the determinism run is in the full set.
    assert triggers["schedule"] == [{"cron": "17 4 * * *"}]
    assert "workflow_dispatch" in triggers


def test_the_job_names_are_stable() -> None:
    jobs = _workflow()["jobs"]
    assert {job_id: job["name"] for job_id, job in jobs.items()} == JOB_NAMES
    assert jobs["check"]["needs"] == "changes"
    # The determinism run reads no path filter: the label decides on a pull request.
    assert "needs" not in jobs["determinism"]


def test_the_integration_branch_requires_the_golden_jobs() -> None:
    text = GUIDE.read_text(encoding="utf-8")
    block = re.search(r"<!-- required-checks-integration -->\n```text\n(.*?)```", text, re.DOTALL)
    assert block is not None, ".github/AGENTS.md lists integration/unified-core's extra checks"
    assert block.group(1).splitlines() == [JOB_NAMES[job] for job in REQUIRED]
    # None of them may be informational.
    for job in _workflow()["jobs"].values():
        assert job.get("continue-on-error") is not True


@pytest.mark.parametrize("result", ["success", "failure", "skipped"])
@pytest.mark.parametrize("golden", ["true", "false", ""])
def test_the_check_runs_on_every_full_ci_pull_request(result: str, golden: str) -> None:
    condition = _workflow()["jobs"]["check"]["if"]
    assert _evaluate(condition, _context("pull_request", INTEGRATION, result, golden, FULL_CI))


@pytest.mark.parametrize(
    ("job", "event", "base", "result", "golden", "labels", "runs"),
    [
        # Every base takes the path filter, integration/unified-core too.
        ("check", "pull_request", INTEGRATION, "success", "false", "", False),
        ("check", "pull_request", INTEGRATION, "success", "true", "", True),
        ("check", "pull_request", INTEGRATION, "failure", "", "", True),
        ("check", "pull_request", INTEGRATION, "success", "false", "perf", False),
        ("check", "pull_request", "development", "success", "false", FULL_CI, True),
        ("check", "pull_request", "development", "success", "false", "", False),
        ("check", "pull_request", "development", "success", "true", "", True),
        ("check", "pull_request", "feat/stacked", "success", "false", "", False),
        # The filter fails open.
        ("check", "pull_request", "development", "failure", "", "", True),
        # Determinism is in the full set: on a pull request, only with the label,
        # whatever the base and whatever changed.
        ("determinism", "pull_request", INTEGRATION, "success", "true", "", False),
        ("determinism", "pull_request", "development", "success", "true", "", False),
        ("determinism", "pull_request", INTEGRATION, "success", "", "", False),
        ("determinism", "pull_request", "development", "success", "false", "perf", False),
        ("determinism", "pull_request", INTEGRATION, "success", "false", FULL_CI, True),
        ("determinism", "pull_request", "development", "success", "false", f"perf,{FULL_CI}", True),
        # Pushes, the schedule and Run workflow run both.
        ("check", "push", "", "success", "true", "", True),
        ("determinism", "push", "", "success", "true", "", True),
        ("determinism", "schedule", "", "success", "true", "", True),
        # (determinism needs no job: `changes` failing does not skip it.)
        ("determinism", "workflow_dispatch", "", "success", "", "", True),
    ],
)
def test_when_each_job_runs(
    job: str, event: str, base: str, result: str, golden: str, labels: str, runs: bool
) -> None:
    condition = _workflow()["jobs"][job]["if"]
    assert _evaluate(condition, _context(event, base, result, golden, labels)) is runs


def test_the_evaluator_reads_labels() -> None:
    condition = "contains(github.event.pull_request.labels.*.name, 'full-ci')"
    assert _evaluate(condition, _context("pull_request", "", "success", "", FULL_CI))
    assert not _evaluate(condition, _context("pull_request", "", "success", "", "full-ci-x"))
    assert not _evaluate(condition, _context("pull_request", "", "success", ""))


@pytest.mark.parametrize("job", ["check"])
def test_without_not_cancelled_a_failed_filter_skips_the_job(job: str) -> None:
    # GitHub adds `success()` to an `if` with no status function, so dropping
    # `!cancelled() &&` skips the job (a passing check) when `Golden paths`
    # fails: the fail-open is gone. The evaluator must see that.
    condition = _workflow()["jobs"][job]["if"]
    assert condition.lstrip().startswith("!cancelled() && (")
    mutated = condition.replace("!cancelled() && (", "(", 1)
    failed = _context("pull_request", INTEGRATION, "failure", "")
    assert _evaluate(condition, failed) is True
    assert _evaluate(mutated, failed) is False
    assert _evaluate(mutated, _context("push", "", "success", "true")) is True


@pytest.mark.parametrize(
    ("condition", "result", "runs"),
    [
        ("github.event_name == 'push'", "success", True),
        ("github.event_name == 'push'", "failure", False),
        ("github.event_name == 'push'", "skipped", False),
        ("always() && github.event_name == 'push'", "failure", True),
        ("failure()", "failure", True),
        ("failure()", "success", False),
        ("!cancelled()", "skipped", True),
        ("cancelled()", "success", False),
    ],
)
def test_the_evaluator_models_status_functions(condition: str, result: str, runs: bool) -> None:
    assert _evaluate(condition, _context("push", "", result, "true")) is runs


def test_the_filter_keeps_the_previous_paths() -> None:
    patterns = [line for line in _paths_step()["env"]["GOLDEN_PATHS"].splitlines() if line]
    assert patterns == GOLDEN_PATHS


GIT_CONFIG = ["-c", "commit.gpgsign=false", "-c", "init.defaultBranch=base"]


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *GIT_CONFIG, *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "--allow-empty", "-q", "-m", message)


def _run_filter(repo: Path, tmp_path: Path, event: str = "pull_request") -> str:
    """Run the `changes` step's script in `repo`; return its `golden` output."""
    step = _paths_step()
    output = tmp_path / "github_output"
    output.write_text("", encoding="utf-8")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "EVENT_NAME": event,
        "GOLDEN_PATHS": step["env"]["GOLDEN_PATHS"],
        "GITHUB_OUTPUT": str(output),
    }
    subprocess.run(
        ["bash", "-c", step["run"]], cwd=repo, env=env, check=True, capture_output=True, text=True
    )
    lines = output.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1, lines
    key, _, value = lines[0].partition("=")
    assert key == "golden"
    return value


def _pull_request(tmp_path: Path, change: dict[str, str | None]) -> Path:
    """A repository whose HEAD is a pull request's merge commit: base, then a
    branch that writes (or, for None, deletes) each path, merged into base."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "base")
    for path in ("src/opentide/cli.py", "xtask/src/main.rs", "README.md"):
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        (repo / path).write_text("base\n", encoding="utf-8")
    _commit(repo, "base")
    _git(repo, "switch", "-q", "-c", "topic")
    for path, content in change.items():
        if content is None:
            _git(repo, "rm", "-q", path)
        else:
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            (repo / path).write_text(content, encoding="utf-8")
    _commit(repo, "topic")
    _git(repo, "switch", "-q", "base")
    (repo / "README.md").write_text("base moved on\n", encoding="utf-8")
    _commit(repo, "base moved on")
    _git(repo, "merge", "-q", "--no-ff", "--no-edit", "topic")
    return repo


@pytest.mark.parametrize(
    ("change", "golden"),
    [
        ({"src/opentide/cli.py": "changed\n"}, "false"),
        ({"docs/cli/index.md": "new\n"}, "false"),
        ({"tests/golden/cases/x/stdout": "new\n"}, "true"),
        ({"tests/fixtures/tide_corpus/a.yaml": "new\n"}, "true"),
        ({"tests/corpora/heavy/seed": "new\n"}, "true"),
        ({"xtask/src/golden/run.rs": "changed\n"}, "true"),
        ({"xtask/src/corpus/x.rs": "new\n"}, "true"),
        ({"xtask/src/compare.rs": "new\n"}, "true"),
        ({"crates/opentide-compare/src/json.rs": "new\n"}, "true"),
        # The rest of the toolchain does not change the frozen oracle's output.
        ({"xtask/src/main.rs": "changed\n"}, "false"),
        ({"xtask/src/main.rs": None}, "false"),
        ({".cargo/config.toml": "new\n"}, "false"),
        ({".gitattributes": "* text=auto\n"}, "false"),
        ({"Cargo.toml": "[workspace]\n"}, "false"),
        ({"Cargo.lock": "version = 4\n"}, "false"),
        ({"rust-toolchain.toml": "[toolchain]\n"}, "false"),
        ({".github/workflows/golden.yml": "name: Golden\n"}, "true"),
        # Near misses are not golden inputs.
        ({"crates/xtask/src/lib.rs": "new\n"}, "false"),
        ({"tests/golden.py": "new\n"}, "false"),
        ({".github/workflows/ci.yml": "name: CI\n"}, "false"),
        ({"src/opentide/cli.py": "changed\n", "tests/golden/cases.toml": "x\n"}, "true"),
    ],
)
def test_the_filter_reads_the_pull_requests_changes(
    tmp_path: Path, change: dict[str, str | None], golden: str
) -> None:
    repo = _pull_request(tmp_path, change)
    assert _run_filter(repo, tmp_path) == golden


def test_a_moved_golden_input_counts_from_its_old_path(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "base")
    (repo / "xtask" / "src" / "golden").mkdir(parents=True)
    (repo / "xtask" / "src" / "golden" / "big.rs").write_text(
        "fn main() {}\n" * 50, encoding="utf-8"
    )
    _commit(repo, "base")
    _git(repo, "switch", "-q", "-c", "topic")
    (repo / "elsewhere").mkdir()
    _git(repo, "mv", "xtask/src/golden/big.rs", "elsewhere/big.rs")
    _commit(repo, "move")
    _git(repo, "switch", "-q", "base")
    _git(repo, "merge", "-q", "--no-ff", "--no-edit", "topic")
    assert _run_filter(repo, tmp_path) == "true"


def test_the_filter_fails_open(tmp_path: Path) -> None:
    repo = _pull_request(tmp_path, {"src/opentide/cli.py": "changed\n"})
    assert _run_filter(repo, tmp_path) == "false"
    # Not a pull request: everything runs.
    assert _run_filter(repo, tmp_path, event="push") == "true"
    # Not a merge commit (no pull request merge ref): everything runs.
    _git(repo, "reset", "-q", "--hard", "HEAD^1")
    assert _run_filter(repo, tmp_path) == "true"
