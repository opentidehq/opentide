"""The frozen Python oracle's comparisons left CI (the maintainer's decision,
2026-11-14).

The oracle is opentide's last Python release, pinned in tests/golden/ORACLE;
the goldens are what it printed and wrote. While the command line was ported
to Rust, CI held the port to those recordings byte for byte: golden.yml's
check and determinism runs, golden-preview.yml, ci.yml's golden compare, the
corpora, the MCP replay, the payload, config, validate and lint diffs, and
codegen's oracle comparisons. The port is done: no workflow runs them, and the
approved-differences ledger gates nothing. Their xtask commands stay, runnable
by hand (tests/golden/README.md, the golden skill).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"

# The oracle's comparisons, as a workflow step would run them.
ORACLE_COMMANDS = [
    r"\bxtask golden (check|diff|record)\b",
    r"--check-determinism",
    r"\bxtask corpus (faults|clean|codes|coverage)\b",
    r"\bxtask (schema|registry|config|payloads|vocab) diff\b",
    r"\bxtask payloads git\b",
    r"\bxtask (validate|lint) diff\b",
    r"\bxtask mcp replay\b",
    r"\bxtask compare\b",
    r"\bxtask golden\b",
    r"--oracle\b",
    r"\bxtask lsp parity\b",
    r"--against python",
    r"--engine python",
    r"\bcodegen --check --oracle\b",
    r"REPORT_ONLY",
]


def _steps() -> list[tuple[str, str, dict[str, Any]]]:
    found = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_id, job in (workflow.get("jobs") or {}).items():
            for step in job.get("steps") or []:
                found.append((path.name, job_id, step))
    return found


@pytest.mark.parametrize("pattern", ORACLE_COMMANDS)
def test_no_workflow_runs_an_oracle_comparison(pattern: str) -> None:
    for name, job_id, step in _steps():
        run = str(step.get("run", ""))
        assert not re.search(pattern, run), (name, job_id, step.get("name"))


def test_the_golden_workflows_are_gone() -> None:
    for name in ("golden.yml", "golden-preview.yml"):
        assert not (WORKFLOWS / name).exists(), name
    text = (ROOT / ".github" / "AGENTS.md").read_text(encoding="utf-8")
    block = re.search(r"<!-- required-checks -->\n```text\n(.*?)```", text, re.DOTALL)
    assert block is not None
    for name in ("Golden compare", "Golden check (python)", "Golden paths", "Corpus"):
        assert not any(line.startswith(name) for line in block.group(1).splitlines()), name
    assert "required-checks-integration" not in text


def test_the_build_checks_the_generated_artifacts_without_the_oracle() -> None:
    ci = yaml.safe_load((WORKFLOWS / "ci.yml").read_text(encoding="utf-8"))
    runs = [str(step.get("run", "")) for step in ci["jobs"]["build"]["steps"]]
    assert "target/debug/xtask codegen --check" in runs
    assert not any("--oracle" in run for job in ci["jobs"].values() for run in _runs(job))


def _runs(job: dict[str, Any]) -> list[str]:
    return [str(step.get("run", "")) for step in job.get("steps") or []]


def test_the_guides_say_the_commands_run_by_hand() -> None:
    """Whoever re-records runs the determinism check, and the comparisons
    stay documented as commands to run by hand."""
    for guide in (ROOT / "tests/golden/README.md", ROOT / ".agents/skills/golden/SKILL.md"):
        text = guide.read_text(encoding="utf-8")
        assert "golden record --check-determinism" in text, guide
        assert "by hand" in text, guide
