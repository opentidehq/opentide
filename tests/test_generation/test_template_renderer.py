"""Template renderer writes FieldInfo YAML for core and enabled platforms."""

from __future__ import annotations

from pathlib import Path

from opentide.cli.enums import DetectionPlatform
from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup
from opentide.package.paths import recomposition_platforms_root


def test_template_renderer_run_writes_core_and_enabled_platform(
    tmp_path: Path, monkeypatch
) -> None:
    from tests.test_cli.conftest import _clear_runtime_caches

    from opentide.core.registry import OpenTide
    from opentide.generation.template_renderer import run as template_renderer_run

    target = tmp_path / "detections"
    run_repo_setup(
        RepoSetupOptions(
            path=target,
            name="Renderer Repo",
            platforms=[DetectionPlatform.sentinel],
            yes=True,
        )
    )
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(target))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(target))
    monkeypatch.delenv("OPENTIDE_DATA_ROOT", raising=False)
    _clear_runtime_caches()
    OpenTide.initialise()
    template_renderer_run()
    rule = (target / ".opentide" / "templates" / "rule.1.0.template.yaml").read_text(
        encoding="utf-8"
    )
    threat = (target / ".opentide" / "templates" / "threat.1.0.template.yaml").read_text(
        encoding="utf-8"
    )
    assert "null" not in rule
    assert "configurations: {}" not in rule
    assert "#sentinel:" in rule
    assert "att&ck:" in threat
    sentinel = (
        recomposition_platforms_root()
        / "MDR Systems Deployment"
        / "Templates"
        / "Microsoft Sentinel Template.yaml"
    )
    platform_text = sentinel.read_text(encoding="utf-8")
    assert "query: |" in platform_text
    assert "schema: platform::sentinel::1.0" in platform_text
    _clear_runtime_caches()
