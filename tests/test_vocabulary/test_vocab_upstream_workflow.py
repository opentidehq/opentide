"""Guards for the weekly ATT&CK + MISP ingest workflow."""

from __future__ import annotations

from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "vocab-upstream.yml"


def test_ingest_creates_pr_when_previous_cycle_is_merged() -> None:
    """``gh pr view <branch>`` matches merged PRs and would skip later cycles."""
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "gh pr view" not in text
    assert text.count("gh pr list") >= 4
    assert text.count("--state open") >= 4
    assert "gh pr create --repo OpenTideHQ/specifications" in text
    assert "gh pr create --base development" in text


def test_ingest_fetches_existing_branch_before_force_push() -> None:
    """``--force-with-lease`` needs origin/$UPSTREAM_BRANCH or later cycles fail."""
    text = WORKFLOW.read_text(encoding="utf-8")
    fetch = 'git fetch origin "$UPSTREAM_BRANCH:refs/remotes/origin/$UPSTREAM_BRANCH"'
    assert text.count(fetch) == 2
    assert text.count("git push --force-with-lease origin") == 2
    specs_checkout = text.split("Checkout specifications", 1)[1]
    assert "fetch-depth: 0" in specs_checkout.split("- uses:", 1)[0]
