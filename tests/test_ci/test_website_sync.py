"""docs.yml's `website` job: opentidehq/website's own sync and build on this tree's docs/.

The website syncs docs/ every hour; a page it refuses or cannot build stops the
site updating, silently. The job must build the site from this run's own tree,
not from the branch the website's .gitmodules names.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / ".github" / "workflows" / "docs.yml"
SCRIPT = ROOT / "scripts" / "ci" / "website-sync.sh"


def _job() -> dict[str, Any]:
    return yaml.safe_load(DOCS.read_text(encoding="utf-8"))["jobs"]["website"]


def test_the_website_guard_builds_the_site_from_this_runs_docs() -> None:
    job = _job()
    checkouts = {
        str((step.get("with") or {}).get("path", ".")): step.get("with") or {}
        for step in job["steps"]
        if str(step.get("uses", "")).startswith("actions/checkout@")
    }
    assert checkouts["website"]["repository"] == "opentidehq/website"
    assert checkouts["website"]["ref"] == "main"
    assert checkouts["website/vendor/specifications"]["repository"] == "opentidehq/specifications"
    assert checkouts["website/vendor/specifications"]["ref"] == "main"
    # This run's tree: no other repository, no other ref.
    ours = checkouts["website/vendor/opentide"]
    assert "repository" not in ours and "ref" not in ours
    assert ours["sparse-checkout"] == "docs"
    assert all(c.get("persist-credentials") is False for c in checkouts.values())
    runs = [str(step.get("run", "")) for step in job["steps"]]
    assert "pnpm install --frozen-lockfile" in "\n".join(runs)
    steps = [run.split()[1] for run in runs if run.startswith("scripts/ci/website-sync.sh")]
    assert steps == ["sync", "test", "build", "verify"]


def test_the_guard_skips_only_the_websites_own_gitlinks_test() -> None:
    guard = SCRIPT.read_text(encoding="utf-8")
    assert guard.count("--test-skip-pattern=") == 1
    assert 'pattern=\\"workspace committed docs match vendor gitlinks\\"' in guard
    assert "pnpm exec next build" in guard and "pnpm sync:content" in guard


def test_the_guard_runs_when_docs_or_it_change() -> None:
    on = yaml.safe_load(DOCS.read_text(encoding="utf-8"))
    triggers = on.get("on", on.get(True))
    for event in ("push", "pull_request"):
        paths = triggers[event]["paths"]
        assert "docs/**" in paths and "scripts/ci/website-sync.sh" in paths, event
