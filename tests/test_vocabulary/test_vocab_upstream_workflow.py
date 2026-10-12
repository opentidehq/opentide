"""Guards for the weekly ATT&CK + MISP ingest workflow.

The two string-presence guards below were green on every commit while the
workflow itself failed every scheduled run from its introduction: the OpenTide
PR step was not gated on the App credential the specifications step already
required, so it fell back to ``GITHUB_TOKEN``, force-pushed
``chore/vocab-upstream``, and only then died on ``gh pr create`` with ``GitHub
Actions is not permitted to create or approve pull requests``. The branch moved
weekly and no reviewer ever saw a PR.

Asserting a command is *present* cannot catch that. The credential invariants
further down are structural: they parse the workflow and check that every step
which writes outside the runner requires the credential needed to finish the
job, so a future unguarded write fails here instead of in production.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "vocab-upstream.yml"

APP_TOKEN_GUARD = "steps.app.outputs.token != ''"

# Shell fragments that mutate something outside the runner.
WRITE_VERBS = ("git push", "gh pr create")


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


def _steps() -> list[dict[str, Any]]:
    document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return [
        step
        for job in document["jobs"].values()
        for step in job.get("steps", [])
        if isinstance(step, dict)
    ]


def _writing_steps() -> list[dict[str, Any]]:
    return [
        step for step in _steps() if any(verb in str(step.get("run", "")) for verb in WRITE_VERBS)
    ]


def test_no_step_condition_uses_the_secrets_context() -> None:
    """``secrets`` in ``steps.if`` makes GitHub reject the file, so no trigger registers."""
    offenders = [
        step.get("name", "<unnamed>") for step in _steps() if "secrets." in str(step.get("if", ""))
    ]
    assert not offenders, f"these conditions would unregister the workflow: {offenders}"


def test_every_writing_step_is_guarded_on_the_app_token() -> None:
    """A step that pushes or opens a PR must require the App credential."""
    unguarded = [
        step.get("name", step.get("uses", "<unnamed>"))
        for step in _writing_steps()
        if APP_TOKEN_GUARD not in str(step.get("if", ""))
    ]
    assert not unguarded, (
        f"these steps write without requiring the App token: {unguarded}. A write that "
        "falls back to GITHUB_TOKEN pushes a branch it cannot open a PR for."
    )


def test_writing_steps_do_not_fall_back_to_the_actions_token() -> None:
    """``GITHUB_TOKEN`` cannot open these PRs, so a write must not accept it."""
    offenders = [
        step.get("name", "<unnamed>")
        for step in _writing_steps()
        if "secrets.GITHUB_TOKEN" in str(step.get("env", {}).get("GH_TOKEN", ""))
    ]
    assert not offenders, (
        f"these writing steps still accept GITHUB_TOKEN: {offenders}. That fallback is "
        "what produced a pushed branch with no PR."
    )


def test_both_pr_steps_share_one_guard() -> None:
    """The two PR steps diverged once; require them to agree."""
    pr_steps = {
        step["name"]: str(step.get("if", ""))
        for step in _steps()
        if "gh pr create" in str(step.get("run", ""))
    }
    assert len(pr_steps) == 2, f"expected two PR-opening steps, found {list(pr_steps)}"
    assert all(APP_TOKEN_GUARD in condition for condition in pr_steps.values()), (
        f"PR steps disagree on their credential guard: {pr_steps}"
    )


def test_preflight_fails_fast_when_the_credential_is_absent() -> None:
    """Without the credential the job must stop before it mutates anything."""
    steps = _steps()
    preflight = next((step for step in steps if "HAS_APP" in str(step.get("if", ""))), None)
    assert preflight is not None, (
        "no step asserts HAS_APP; a credential-less run would reach the writes"
    )
    assert "exit 1" in str(preflight["run"]), "preflight must fail the job"

    first_write = min(
        (
            index
            for index, step in enumerate(steps)
            if any(verb in str(step.get("run", "")) for verb in WRITE_VERBS)
        ),
        default=len(steps),
    )
    assert steps.index(preflight) < first_write, (
        "preflight runs after a write; the branch would already have moved"
    )


@pytest.mark.parametrize("secret", ["GH_APP_ID", "GH_APP_KEY"])
def test_preflight_names_the_missing_secret(secret: str) -> None:
    """A maintainer reading the failure needs to know what to configure."""
    preflight = next(step for step in _steps() if "HAS_APP" in str(step.get("if", "")))
    assert secret in str(preflight["run"])
