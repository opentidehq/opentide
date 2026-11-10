"""golden.yml runs on every pull request into integration/unified-core (#803).

Branch protection on ``integration/unified-core`` requires golden.yml's checks
(the second list in ``.github/AGENTS.md``). A required check that never starts
blocks the merge, so the ``pull_request`` trigger takes no path or branch
filter: the ``changes`` job (``Golden paths``) filters by path inside the
workflow, and a job its ``if`` skips reports success.

- ``Golden check (python)`` runs on every pull request into the integration
  branch, and on other bases when a golden input changed.
- ``Golden determinism`` records every case twice (about 26 minutes), so it
  stays path-filtered on every base.
- Both run when the filter did not succeed, and on every push and schedule.
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

# The jobs branch protection requires, by id: renaming one breaks the rule.
JOB_NAMES = {
    "changes": "Golden paths",
    "check": "Golden check (python)",
    "determinism": "Golden determinism",
}

# The pull_request path filter golden.yml had before #803, as bash patterns,
# plus the renderers' oracle snapshots and their driver (UC-3.4, #826).
GOLDEN_PATHS = [
    "tests/golden/*",
    "tests/fixtures/tide_corpus/*",
    "scripts/golden/*",
    "crates/opentide-cli/tests/render/*",
    "tests/corpora/*",
    "xtask/*",
    ".cargo/*",
    ".gitattributes",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
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


def _evaluate(condition: str, context: dict[str, str]) -> bool:
    """Evaluate a job's `if` for one event: the subset of GitHub's expression
    language golden.yml uses (status functions, `!`, `&&`, `||`, `==`, `!=`).

    As on GitHub, a condition with no status function gets an implicit
    `success()`: the job is skipped when a job it needs did not succeed."""
    if not STATUS.search(condition):
        condition = f"success() && ({condition})"
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
    names = re.compile(r"\b(?:github|needs)\.[A-Za-z0-9_.]+")
    unknown = {name for name in names.findall(expression) if name not in context}
    assert not unknown, f"the test does not know {unknown}"
    expression = names.sub(lambda m: repr(context[m.group(0)]), expression)
    # Only literals, names and operators are left: the workflow's own text.
    assert re.fullmatch(r"[\sA-Za-z0-9_'()/=!.-]*", expression), expression
    return bool(eval(expression, {"__builtins__": {}}))


def _context(event: str, base: str, result: str, golden: str) -> dict[str, str]:
    return {
        "github.event_name": event,
        "github.base_ref": base,
        "needs.changes.result": result,
        "needs.changes.outputs.golden": golden,
    }


def test_the_pull_request_trigger_has_no_filter() -> None:
    # A path filter back on the trigger means a required check that never
    # starts on most pull requests into integration/unified-core.
    pull_request = _triggers()["pull_request"] or {}
    assert pull_request == {}, f"golden.yml's pull_request trigger is filtered: {pull_request}"


def test_push_and_schedule_are_unchanged() -> None:
    triggers = _triggers()
    assert triggers["push"] == {"branches": ["development", INTEGRATION]}
    assert triggers["schedule"] == [{"cron": "17 4 * * 1"}]
    assert "workflow_dispatch" in triggers


def test_the_job_names_are_stable() -> None:
    jobs = _workflow()["jobs"]
    assert {job_id: job["name"] for job_id, job in jobs.items()} == JOB_NAMES
    assert jobs["check"]["needs"] == "changes"
    assert jobs["determinism"]["needs"] == "changes"


def test_the_integration_branch_requires_the_golden_jobs() -> None:
    text = GUIDE.read_text(encoding="utf-8")
    block = re.search(r"<!-- required-checks-integration -->\n```text\n(.*?)```", text, re.DOTALL)
    assert block is not None, ".github/AGENTS.md lists integration/unified-core's extra checks"
    assert block.group(1).splitlines() == list(JOB_NAMES.values())
    # None of them may be informational.
    for job in _workflow()["jobs"].values():
        assert job.get("continue-on-error") is not True


@pytest.mark.parametrize("result", ["success", "failure", "skipped"])
@pytest.mark.parametrize("golden", ["true", "false", ""])
def test_the_check_runs_on_every_pull_request_into_integration(result: str, golden: str) -> None:
    condition = _workflow()["jobs"]["check"]["if"]
    assert _evaluate(condition, _context("pull_request", INTEGRATION, result, golden))


@pytest.mark.parametrize(
    ("job", "event", "base", "result", "golden", "runs"),
    [
        # Other bases keep the path filter.
        ("check", "pull_request", "development", "success", "false", False),
        ("check", "pull_request", "development", "success", "true", True),
        ("check", "pull_request", "feat/stacked", "success", "false", False),
        # Determinism is path-filtered on every base, the integration branch included.
        ("determinism", "pull_request", INTEGRATION, "success", "false", False),
        ("determinism", "pull_request", INTEGRATION, "success", "true", True),
        ("determinism", "pull_request", "development", "success", "false", False),
        ("determinism", "pull_request", "development", "success", "true", True),
        # The filter fails open.
        ("check", "pull_request", "development", "failure", "", True),
        ("determinism", "pull_request", INTEGRATION, "failure", "", True),
        # Pushes, the schedule and Run workflow run both.
        ("check", "push", "", "success", "true", True),
        ("determinism", "push", "", "success", "true", True),
        ("determinism", "schedule", "", "success", "true", True),
        ("determinism", "workflow_dispatch", "", "failure", "", True),
    ],
)
def test_when_each_job_runs(
    job: str, event: str, base: str, result: str, golden: str, runs: bool
) -> None:
    condition = _workflow()["jobs"][job]["if"]
    assert _evaluate(condition, _context(event, base, result, golden)) is runs


@pytest.mark.parametrize("job", ["check", "determinism"])
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
        ({"xtask/src/main.rs": "changed\n"}, "true"),
        ({"xtask/src/main.rs": None}, "true"),
        ({".cargo/config.toml": "new\n"}, "true"),
        ({".gitattributes": "* text=auto\n"}, "true"),
        ({"Cargo.toml": "[workspace]\n"}, "true"),
        ({"Cargo.lock": "version = 4\n"}, "true"),
        ({"rust-toolchain.toml": "[toolchain]\n"}, "true"),
        ({".github/workflows/golden.yml": "name: Golden\n"}, "true"),
        # Near misses are not golden inputs.
        ({"crates/xtask/src/lib.rs": "new\n"}, "false"),
        ({"tests/golden.py": "new\n"}, "false"),
        ({".github/workflows/ci.yml": "name: CI\n"}, "false"),
        ({"src/opentide/cli.py": "changed\n", "Cargo.lock": "version = 4\n"}, "true"),
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
    (repo / "xtask").mkdir()
    (repo / "xtask" / "big.rs").write_text("fn main() {}\n" * 50, encoding="utf-8")
    _commit(repo, "base")
    _git(repo, "switch", "-q", "-c", "topic")
    (repo / "elsewhere").mkdir()
    _git(repo, "mv", "xtask/big.rs", "elsewhere/big.rs")
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
