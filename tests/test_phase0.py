"""Phase 0 acceptance tests — CDM/BDR removal."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN = ("src/Engines",)


def test_cdm_absent() -> None:
    r = subprocess.run(
        ["git", "grep", "-in", r"\bcdm\b", "--", *SCAN], cwd=ROOT, capture_output=True, text=True
    )
    assert r.returncode == 1, r.stdout


def test_bdr_absent() -> None:
    r = subprocess.run(
        ["git", "grep", "-in", r"\bbdr\b", "--", *SCAN], cwd=ROOT, capture_output=True, text=True
    )
    assert r.returncode == 1, r.stdout


def test_dom_template_bug_fixed() -> None:
    global_toml = (ROOT / "src/opentide/data/configurations/global.toml").read_text()
    assert '"dom"' in global_toml
    assert '"cdm"' not in global_toml


def test_global_objects() -> None:
    assert (
        'objects = [ "tvm", "dom", "mdr" ]'
        in (ROOT / "src/opentide/data/configurations/global.toml").read_text()
    )


def test_deleted_files() -> None:
    assert not (ROOT / "src/Engines/mutation/remove_cdm_validation.py").exists()
    assert not (ROOT / "Framework/Meta Schemas/CDM Meta Schema.yaml").exists()


def test_indent_full_dumper_centralized() -> None:
    source = (ROOT / "src/opentide/core/files.py").read_text()
    assert "class IndentFullDumper(yaml.Dumper):" in source
    engines_shim = (ROOT / "src/Engines/modules/files.py").read_text()
    assert "from opentide.core.files import" in engines_shim
    shim_body = engines_shim.replace("from opentide.core.files import", "")
    assert "class IndentFullDumper" not in shim_body


def test_ordered_yaml_dumper_renamed() -> None:
    r = subprocess.run(
        ["git", "grep", "-n", "class MyDumper", "--", "src/Engines", "src/opentide"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 1, r.stdout
    source = (ROOT / "src/opentide/core/files.py").read_text()
    assert "class OrderedYAMLDumper(IndentFullDumper):" in source
    refs = (ROOT / "src/Engines/mutation/references.py").read_text()
    assert "MyDumper" not in refs
    assert "OrderedYAMLDumper" not in refs


def test_seven_platforms_five_validators() -> None:
    bundled = ROOT / "src/opentide/data/configurations/platforms"
    systems = {p.name for p in bundled.glob("*.toml")}
    assert len(systems) == 7
    validators = {
        p.stem.replace("_query", "") for p in (ROOT / "src/Engines/validation").glob("*_query.py")
    }
    assert validators == {
        "carbon_black_cloud",
        "defender_for_endpoint",
        "sentinel",
        "sentinel_one",
        "splunk",
    }
