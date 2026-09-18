"""Golden YAML skeletons from the FieldInfo renderer."""

from __future__ import annotations

import re
from pathlib import Path

from opentide.generation.pydantic_skeleton import render_model_template, write_model_template
from opentide.generation.pydantic_templates import core_schema_models, generate_core_template
from opentide.models.platform import PLATFORM_CONFIG_MODELS
from opentide.models.platform_schema import platform_model_for_key

ROOT = Path(__file__).resolve().parents[2]
CORE_GOLDENS = ROOT / "tests/fixtures/generation/tide_workspace/.opentide/templates"
PLATFORM_GOLDENS = (
    ROOT / "src/opentide/schemas/data/platform_templates/MDR Systems Deployment/Templates"
)

CORE_FILES = {
    "threat": "threat.1.0.template.yaml",
    "objective": "objective.1.0.template.yaml",
    "rule": "rule.1.0.template.yaml",
}

PLATFORM_FILES = {
    "sentinel": "Microsoft Sentinel Template.yaml",
    "defender_for_endpoint": "Microsoft Defender for Endpoint Template.yaml",
    "splunk": "Splunk Enterprise Template.yaml",
    "sentinel_one": "Sentinel One Template.yaml",
    "crowdstrike": "Crowdstrike Falcon Correlation Rules Template.yaml",
    "harfanglab": "HarfangLab Template.yaml",
    "carbon_black_cloud": "Carbon Black Cloud Enterprise EDR Template.yaml",
}


def test_core_template_goldens_match_renderer() -> None:
    models = core_schema_models()
    for key, filename in CORE_FILES.items():
        model = models[key]
        rendered = render_model_template(model, schema_id=model.schema_identifier())
        expected = (CORE_GOLDENS / filename).read_text(encoding="utf-8")
        assert rendered == expected, filename
        assert "null" not in rendered
        assert re.search(r"(?m)^[ ]*#[ ]+#", rendered) is None


def test_platform_template_goldens_match_renderer() -> None:
    for key, filename in PLATFORM_FILES.items():
        model = platform_model_for_key(key)
        expected = (PLATFORM_GOLDENS / filename).read_text(encoding="utf-8")
        rendered = render_model_template(model, indent=2)
        assert rendered == expected, filename
        assert "null" not in rendered
        assert "configurations: {}" not in rendered
        assert re.search(r"(?m)^[ ]*#[ ]+#", rendered) is None


def test_platform_models_cover_golden_files() -> None:
    assert set(PLATFORM_FILES) == set(PLATFORM_CONFIG_MODELS)


def test_generate_core_template_writes_golden_bytes(tmp_path: Path) -> None:
    for key, filename in CORE_FILES.items():
        path = tmp_path / filename
        generate_core_template(key, path)
        assert path.read_text(encoding="utf-8") == (CORE_GOLDENS / filename).read_text(
            encoding="utf-8"
        )


def test_write_model_template_matches_platform_golden(tmp_path: Path) -> None:
    path = tmp_path / "Microsoft Sentinel Template.yaml"
    write_model_template(path, platform_model_for_key("sentinel"), indent=2)
    golden = (PLATFORM_GOLDENS / PLATFORM_FILES["sentinel"]).read_text(encoding="utf-8")
    assert path.read_text(encoding="utf-8") == golden
