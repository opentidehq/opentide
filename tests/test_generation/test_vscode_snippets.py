"""VS Code snippet generation helpers."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

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
    snippet = vs_code_snippet_generator(template, "tide-rule")
    assert snippet["prefix"] == "tide-rule"
    assert snippet["scope"] == "yaml"
    assert snippet["description"] == "tide-rule"
    assert "name: Example" in snippet["body"]


def test_vs_code_snippet_generator_tabstops_empty_values(tmp_path: Path) -> None:
    template = tmp_path / "rule.yaml"
    template.write_text(
        "name: \nmetadata:\n  uuid: \n  created: YYYY-MM-DD\n  #author: \n  description: |\n    ...\n",
        encoding="utf-8",
    )
    snippet = vs_code_snippet_generator(
        template, "tide-rule", description="Detection Rules Template"
    )
    assert snippet["description"] == "Detection Rules Template"
    body = snippet["body"]
    assert "name: ${1:name}" in body
    assert "metadata:" in body
    assert "metadata: ${" not in "\n".join(body)
    assert "  uuid: ${2:uuid}" in body
    assert "  created: YYYY-MM-DD" in body
    assert "  #author: " in body
    assert "    ${3:...}" in body
    assert not any("${" in line and line.lstrip().startswith("#") for line in body)


def test_vs_code_snippet_generator_prepends_blank_lines(tmp_path: Path) -> None:
    template = tmp_path / "objective.yaml"
    template.write_text("objective:\n", encoding="utf-8")
    snippet = vs_code_snippet_generator(template, "tide-objective", blanks=2)
    assert snippet["body"][0] == ""
    assert snippet["body"][1] == ""
    assert "objective:" in snippet["body"][-1]


def test_run_uses_legacy_subschemas_when_platform_templates_missing(tmp_path: Path) -> None:
    mocked = _mock_opentide_for_snippets(
        tmp_path,
        core=SimpleNamespace(subschemas=str(tmp_path / "legacy-subschemas")),
    )
    with patch("opentide.generation.vscode_snippets.OpenTide", mocked.ot):
        run()
    payload = json.loads(mocked.snippets_file.read_text(encoding="utf-8"))
    assert "Detection Rules Template" in payload
    entry = payload["Detection Rules Template"]
    assert entry["prefix"] == "tide-rule"
    assert entry["scope"] == "yaml"
    assert entry["description"] == "Detection Rules Template"


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
    assert payload["Detection Rules Template"]["prefix"] == "tide-rule"


def test_run_raises_when_enabled_platform_template_missing(tmp_path: Path) -> None:
    mocked = _mock_opentide_for_snippets(
        tmp_path,
        core=SimpleNamespace(platform_templates=str(tmp_path / "missing-platforms")),
        systems={
            "sentinel": {
                "platform": {"enabled": True, "name": "Microsoft Sentinel"},
            }
        },
    )
    with (
        patch("opentide.generation.vscode_snippets.OpenTide", mocked.ot),
        pytest.raises(FileNotFoundError, match="platform sentinel"),
    ):
        run()


def test_run_raises_when_core_template_missing(tmp_path: Path) -> None:
    mocked = _mock_opentide_for_snippets(
        tmp_path,
        core=SimpleNamespace(platform_templates=str(tmp_path / "platform_templates")),
        templates={"rule": "missing-rule.yaml"},
    )
    with (
        patch("opentide.generation.vscode_snippets.OpenTide", mocked.ot),
        pytest.raises(FileNotFoundError, match="core rule"),
    ):
        run()


def test_run_emits_enabled_platform_snippets(tmp_path: Path) -> None:
    platform_root = tmp_path / "platform_templates" / "MDR Systems Deployment" / "Templates"
    platform_root.mkdir(parents=True)
    (platform_root / "Microsoft Sentinel Template.yaml").write_text("query: \n", encoding="utf-8")
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
    assert payload[key]["prefix"] == "tide-sentinel"
    assert payload[key]["scope"] == "yaml"
    assert payload[key]["body"][0] == ""
    assert "query: ${1:query}" in payload[key]["body"]


def test_run_honors_snippets_path_override(tmp_path: Path) -> None:
    mocked = _mock_opentide_for_snippets(
        tmp_path,
        core=SimpleNamespace(platform_templates=str(tmp_path / "platform_templates")),
    )
    override = tmp_path / "custom" / "override.code-snippets"
    import opentide.generation.vscode_snippets as vscode_snippets

    vscode_snippets.SNIPPETS_PATH = str(override)
    try:
        with patch("opentide.generation.vscode_snippets.OpenTide", mocked.ot):
            run()
        assert override.is_file()
        payload = json.loads(override.read_text(encoding="utf-8"))
        assert "Detection Rules Template" in payload
        assert not mocked.snippets_file.exists()
    finally:
        vscode_snippets.SNIPPETS_PATH = None


def test_run_completes_on_fresh_setup_repo(tmp_path: Path, monkeypatch) -> None:
    """Reproduce issue #153: snippets must not crash on a scaffolded empty repo."""
    from tests.test_cli.conftest import _clear_runtime_caches

    from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup
    from opentide.core.registry import OpenTide
    from opentide.generation import vscode_snippets as vscode_snippets_mod
    from opentide.generation.pydantic_templates import generate_core_template

    vscode_snippets_mod.SNIPPETS_PATH = None
    fresh = tmp_path / "fresh"
    run_repo_setup(RepoSetupOptions(path=fresh, name="Fresh", yes=True))
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(fresh))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(fresh))
    monkeypatch.delenv("OPENTIDE_DATA_ROOT", raising=False)
    _clear_runtime_caches()
    OpenTide.initialise()
    templates_dir = fresh / ".opentide" / "templates"
    templates_dir.mkdir(parents=True, exist_ok=True)
    for key in ("rule", "threat", "objective"):
        generate_core_template(key, templates_dir / f"{key}.1.0.template.yaml")
    run()
    snippets = fresh / ".vscode" / "model-templates.code-snippets"
    assert snippets.is_file()
    payload = json.loads(snippets.read_text(encoding="utf-8"))
    assert payload["Detection Rules Template"]["prefix"] == "tide-rule"
    assert payload["Threat Vectors Template"]["prefix"] == "tide-threat"
    assert payload["Detection Objectives Template"]["prefix"] == "tide-objective"
    rule_body = "\n".join(payload["Detection Rules Template"]["body"])
    assert "${1:name}" in rule_body or "name: ${" in rule_body
    assert "#author:" in rule_body
    assert "${" not in "".join(
        line
        for line in payload["Detection Rules Template"]["body"]
        if line.lstrip().startswith("#")
    )
    _clear_runtime_caches()
