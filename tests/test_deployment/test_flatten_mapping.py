"""Tenant modifiers flatten configurations without pandas, to the keys pandas gave (#747).

``tests/fixtures/deployment/modifier_flatten_expected.json`` was captured from
``pandas.json_normalize(data).to_dict(orient="records")[0]`` and from
``TideDeployment.modifiers_resolver`` while it still used pandas: every
``flatten`` case is the flattening of one input, every ``modifiers`` case the
configuration a tenant modifier produced for a ``tide_corpus`` rule. The
replacement must give the same keys, in the same order, the same values and
the same deployed configuration.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
import yaml

from opentide.deployment.planning import TideDeployment, flatten_mapping
from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.deployment_enums import DetectionPlatforms
from opentide.models.system_config import SystemConfig

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = json.loads(
    (ROOT / "tests/fixtures/deployment/modifier_flatten_expected.json").read_text(encoding="utf-8")
)
CORPUS_RULES = ROOT / "tests/fixtures/tide_corpus/current/Objects/Detection Rules"

#: Synthetic inputs whose keys are not strings, which JSON cannot carry.
_NON_STRING_KEYS: dict[str, dict[Any, Any]] = {"int-key": {1: "one", "n": {2: "two"}}}


def _case_input(case: dict[str, Any]) -> dict[Any, Any]:
    return _NON_STRING_KEYS.get(case["id"], case["input"])


def _expected_pairs(case: dict[str, Any]) -> list[tuple[Any, Any]]:
    pairs = [(key, value) for key, value in case["expected"]]
    if case["id"] == "int-key":
        # pandas kept a top-level key as it was and wrote nested ones as text.
        pairs[0] = (1, pairs[0][1])
    return pairs


@pytest.mark.parametrize(
    "case", [case for case in EXPECTED["flatten"] if "error" not in case], ids=lambda c: c["id"]
)
def test_flatten_mapping_gives_the_keys_and_values_pandas_gave(case: dict[str, Any]) -> None:
    flat = flatten_mapping(_case_input(case))

    assert list(flat.items()) == _expected_pairs(case)
    if "types" in case:
        assert [type(value).__name__ for value in flat.values()] == case["types"]


@pytest.mark.parametrize(
    "case", [case for case in EXPECTED["flatten"] if "error" in case], ids=lambda c: c["id"]
)
def test_flatten_mapping_of_nothing_is_empty_where_pandas_raised(case: dict[str, Any]) -> None:
    """pandas made no row of a mapping with nothing to flatten, so ``[0]`` raised IndexError."""
    assert case["error"] == "IndexError"
    assert flatten_mapping(case["input"]) == {}


def test_flatten_mapping_keeps_lists_and_lets_a_nested_key_replace_a_dotted_one() -> None:
    flat = flatten_mapping({"a.b": 1, "a": {"b": 2, "c": [{"d": 3}]}, "e": {}})

    assert list(flat.items()) == [("a.b", 2), ("a.c", [{"d": 3}])]


@pytest.mark.parametrize("case", EXPECTED["modifiers"], ids=lambda c: c["id"])
def test_tenant_modifiers_deploy_the_configuration_they_did_with_pandas(
    case: dict[str, Any], tide_corpus_repo: Path
) -> None:
    del tide_corpus_repo
    platform = case["platform"]
    rule = load_rule_from_dict(
        yaml.safe_load((CORPUS_RULES / case["file"]).read_text(encoding="utf-8"))
    )
    tide = TideDeployment.__new__(TideDeployment)
    tide.system_configuration_resolver = MagicMock(
        return_value=SimpleNamespace(
            platform=SimpleNamespace(identifier=platform),
            modifiers=[
                SystemConfig.Modifiers(
                    name="Lab",
                    conditions=SystemConfig.Modifiers.Conditions(tenants=case["tenants"]),
                    modifications=case["modifications"],
                )
            ],
        )
    )
    system = DetectionPlatforms[platform.upper()]

    if "error" in case:
        with pytest.raises(Exception) as raised:
            tide.modifiers_resolver(rule, "Lab", system)
        assert type(raised.value).__name__ == case["error"]
        return
    modified = tide.modifiers_resolver(rule, "Lab", system)

    config = getattr(modified.configurations, platform)
    assert config.model_dump(mode="json", by_alias=True) == case["config"]
    if "api_request" in case:
        from opentide.deployment.preview import preview_rule_deployment

        preview = preview_rule_deployment(platform, modified)
        assert json.loads(json.dumps(preview["api_request"], default=str)) == case["api_request"]


def test_tenant_modifiers_run_with_pandas_blocked(tmp_path: Path) -> None:
    """Deploy planning applied modifiers through pandas; a stock install has none now."""
    rule_file = str(CORPUS_RULES / "rule-0001-sentinel-kql.yaml")
    script = f"""
import sys

class BlockPandas:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in ("pandas", "numpy", "openpyxl"):
            raise ModuleNotFoundError(fullname + " blocked by regression test")
        return None

sys.meta_path.insert(0, BlockPandas())
from types import SimpleNamespace
from unittest.mock import MagicMock

import yaml

from opentide.deployment.planning import TideDeployment
from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.deployment_enums import DetectionPlatforms
from opentide.models.system_config import SystemConfig

rule = load_rule_from_dict(yaml.safe_load(open({rule_file!r}, encoding="utf-8")))
tide = TideDeployment.__new__(TideDeployment)
tide.system_configuration_resolver = MagicMock(return_value=SimpleNamespace(
    platform=SimpleNamespace(identifier="sentinel"),
    modifiers=[SystemConfig.Modifiers(
        name="Lab",
        conditions=SystemConfig.Modifiers.Conditions(tenants=["Lab"]),
        modifications={{"alert.title": "prefix::[LAB] "}},
    )],
))
modified = tide.modifiers_resolver(rule, "Lab", DetectionPlatforms.SENTINEL)
assert modified.configurations.sentinel.alert.title == "[LAB] Sentinel KQL Rule"
assert "pandas" not in sys.modules
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        check=False,
        text=True,
        cwd=tmp_path,
    )

    assert result.returncode == 0, result.stderr
