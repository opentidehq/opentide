"""Golden markdown snapshots for documentation object pages."""

from __future__ import annotations

import pytest
from tests.test_documentation._snapshot_helpers import (
    github_context,
    load_documentation_bundle,
)

from opentide.documentation.objects.objective import render_objective_page
from opentide.documentation.objects.rule import render_rule_page
from opentide.documentation.objects.threat import render_threat_page


@pytest.mark.parametrize("family", ["threat", "objective", "rule"])
def test_github_markdown_snapshots(family: str, tmp_path, snapshot) -> None:
    bundle = load_documentation_bundle()
    ctx = github_context(tmp_path)

    if family == "threat":
        rendered = render_threat_page(bundle.threat, ctx, bundle.catalog)
    elif family == "objective":
        rendered = render_objective_page(bundle.objective, ctx, bundle.catalog)
    else:
        rendered = render_rule_page(bundle.rule, ctx, bundle.catalog)

    assert rendered == snapshot(name=f"{family}_github")
