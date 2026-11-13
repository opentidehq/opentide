"""The catch-up train's report-only goldens (the plan's golden oracle move).

While ``tests/golden/REPORT_ONLY`` is committed on ``train/catchup-0.28``, the
golden-diff gates report their differences instead of failing: every platform
ported onto the train before the oracle moves (O2) adds explain pages and
diagnostic codes the 0.23.0 recordings do not have. The switch lives in
``xtask``'s ``golden::report_only`` and in the CLI's golden test helper; the
ledger's own check and every unit, fixture and cassette test still gate.

The marker belongs to the train alone. ``ci.yml``'s ``report-only-guard`` job
fails any pull request into ``integration/unified-core`` or ``development``
while it is present, so gating can never be turned off there.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / ".github" / "workflows" / "ci.yml"
MARKER = "tests/golden/REPORT_ONLY"
GATED_BASES = ("integration/unified-core", "development")


def _ci() -> dict:
    return yaml.safe_load(CI.read_text(encoding="utf-8"))


def test_the_guard_job_runs_on_every_pull_request() -> None:
    """A core gate: no ``if``, so it starts on every pull request (and push)."""
    job = _ci()["jobs"]["report-only-guard"]
    assert "if" not in job, "the guard is a core gate: it runs unconditionally"
    assert job["name"] == "Report-only goldens guard"


def test_the_guard_checks_the_marker_against_the_gated_bases() -> None:
    """The step reads github.base_ref and fails on a gated base with the marker."""
    steps = _ci()["jobs"]["report-only-guard"]["steps"]
    run = next(step["run"] for step in steps if "run" in step and MARKER in step["run"])
    assert "github.base_ref" in str(_ci()["jobs"]["report-only-guard"]["steps"]), (
        "the guard reads the pull request's base"
    )
    for base in GATED_BASES:
        assert base in run, f"the guard names {base}"
    # It exits non-zero on a gated base, and tolerates the marker's absence.
    assert "exit 1" in run
    assert f"! -f {MARKER}" in run


def test_the_marker_if_present_explains_itself_and_o2() -> None:
    """When the train commits the marker, it says why and that O2 removes it."""
    marker = ROOT / MARKER
    if not marker.is_file():
        # Absent on a gated base (where this test also runs): nothing to check.
        return
    text = marker.read_text(encoding="utf-8")
    assert "O2" in text
    assert "oracle" in text.lower()
    for base in GATED_BASES:
        assert base in text
