"""VS Code snippet generation helpers."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from opentide.generation.vscode_snippets import run, vs_code_snippet_generator


def _mock_opentide_for_snippets(
    tmp_path: Path,
    *,
    core: SimpleNamespace,
    systems: dict[str, object] | None = None,
    templates: dict[str, str] | None = None,
) -> SimpleNamespace:
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    (templates_dir / "rule.yaml").write_text("name: Example\n", encoding="utf-8")
    snippets_file = tmp_path / ".vscode" / "model-templates.code-snippets"
    paths = SimpleNamespace(
        Index={"templates": str(templates_dir)},
        Tide=SimpleNamespace(
            snippet_file=str(snippets_file),
            templates=str(templates_dir),
        ),
        Core=core,
    )
    ot = SimpleNamespace(
        Configurations=SimpleNamespace(
            Global=SimpleNamespace(
                Paths=paths,
                metaschemas={"rule": "rule"},
                templates=templates or {"rule": "rule.yaml"},
                recomposition={"systems": "MDR Systems Deployment"},
            ),
            Documentation=SimpleNamespace(object_names={"rule": "Detection Rules"}),
            Index={"systems": systems or {}},
        )
    )
    return SimpleNamespace(ot=ot, snippets_file=snippets_file, templates_dir=templates_dir)


def test_vs_code_snippet_generator_reads_template(tmp_path: Path) -> None:
    template = tmp_path / "rule.yaml"
    template.write_text("name: Example\n", encoding="utf-8")
    snippet = vs_code_snippet_generator(template, "Rule Template")
    assert snippet["prefix"] == "Rule Template"
    assert "name: Example" in snippet["body"]


def test_vs_code_snippet_generator_prepends_blank_lines(tmp_path: Path) -> None:
    template = tmp_path / "objective.yaml"
    template.write_text("objective:\n", encoding="utf-8")
    snippet = vs_code_snippet_generator(template, "Objective Template", blanks=2)
    assert snippet["body"][0] == ""
    assert snippet["body"][1] == ""
    assert "objective:" in snippet["body"][-1]


def test_run_uses_platform_templates_when_subschemas_missing(tmp_path: Path) -> None:
    mocked = _mock_opentide_for_snippets(
        tmp_path,
        core=SimpleNamespace(platform_templates=str(tmp_path / "platform_templates")),
    )
    with patch("opentide.generation.vscode_snippets.OpenTide", mocked.ot):
        run()
    payload = json.loads(mocked.snippets_file.read_text(encoding="utf-8"))
    assert "Detection Rules Template" in payload
    assert payload["Detection Rules Template"]["body"] == ["name: Example"]


def test_run_skips_missing_platform_template_instead_of_crashing(tmp_path: Path) -> None:
    mocked = _mock_opentide_for_snippets(
        tmp_path,
        core=SimpleNamespace(platform_templates=str(tmp_path / "missing-platforms")),
        systems={
            "sentinel": {
                "platform": {"enabled": True, "name": "Microsoft Sentinel"},
            }
        },
    )
    with patch("opentide.generation.vscode_snippets.OpenTide", mocked.ot):
        run()
    payload = json.loads(mocked.snippets_file.read_text(encoding="utf-8"))
    assert "Detection Rules Template" in payload
    assert "Microsoft Sentinel" not in json.dumps(payload)


def test_run_emits_enabled_platform_snippets(tmp_path: Path) -> None:
    platform_root = tmp_path / "platform_templates" / "MDR Systems Deployment" / "Templates"
    platform_root.mkdir(parents=True)
    (platform_root / "Microsoft Sentinel Template.yaml").write_text(
        "query: SecurityEvent\n", encoding="utf-8"
    )
    mocked = _mock_opentide_for_snippets(
        tmp_path,
        core=SimpleNamespace(platform_templates=str(tmp_path / "platform_templates")),
        systems={
            "sentinel": {
                "platform": {"enabled": True, "name": "Microsoft Sentinel"},
            }
        },
    )
    with patch("opentide.generation.vscode_snippets.OpenTide", mocked.ot):
        run()
    payload = json.loads(mocked.snippets_file.read_text(encoding="utf-8"))
    key = "MDR Systems Deployment : Microsoft Sentinel Template"
    assert key in payload
    assert payload[key]["body"][0] == ""
    assert "query: SecurityEvent" in payload[key]["body"]


def test_run_completes_on_fresh_setup_repo(tmp_path: Path, monkeypatch) -> None:
    """Reproduce issue #153: snippets must not crash on a scaffolded empty repo."""
    from tests.test_cli.conftest import _clear_runtime_caches

    from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup
    from opentide.core.registry import OpenTide

    fresh = tmp_path / "fresh"
    run_repo_setup(RepoSetupOptions(path=fresh, name="Fresh", yes=True))
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(fresh))
    _clear_runtime_caches()
    OpenTide.initialise()
    run()
    snippets = fresh / ".vscode" / "model-templates.code-snippets"
    assert snippets.is_file()
    json.loads(snippets.read_text(encoding="utf-8"))
