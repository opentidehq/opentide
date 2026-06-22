"""Phase 0 acceptance tests — CDM/BDR removal."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN = ("Engines", "Configurations", "Orchestration")


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
    registry = (ROOT / "Engines/modules/registry.py").read_text()
    assert 'dom = str(Index.get("dom"))' in registry
    assert 'dom = str(Index.get("cdm"))' not in registry


def test_global_objects() -> None:
    assert 'objects = [ "tvm", "dom", "mdr" ]' in (ROOT / "Configurations/global.toml").read_text()


def test_deleted_files() -> None:
    assert not (ROOT / "Engines/mutation/remove_cdm_validation.py").exists()
    assert not (ROOT / "Framework/Meta Schemas/CDM Meta Schema.yaml").exists()


def test_indent_full_dumper_centralized() -> None:
    r = subprocess.run(
        ["git", "grep", "-n", "class IndentFullDumper", "--", "Engines"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    lines = [line for line in r.stdout.strip().splitlines() if line]
    assert len(lines) == 1
    assert lines[0].endswith("class IndentFullDumper(yaml.Dumper):")
    assert lines[0].startswith("Engines/modules/files.py:")


def test_ordered_yaml_dumper_renamed() -> None:
    r = subprocess.run(
        ["git", "grep", "-n", "class MyDumper", "--", "Engines"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 1, r.stdout
    r = subprocess.run(
        ["git", "grep", "-n", "class OrderedYAMLDumper", "--", "Engines"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    lines = [line for line in r.stdout.strip().splitlines() if line]
    assert len(lines) == 1
    assert lines[0].endswith("class OrderedYAMLDumper(IndentFullDumper):")
    assert lines[0].startswith("Engines/modules/files.py:")
    refs = (ROOT / "Engines/mutation/references.py").read_text()
    assert "MyDumper" not in refs
    assert "OrderedYAMLDumper" not in refs


def test_seven_platforms_five_validators() -> None:
    systems = {p.name for p in (ROOT / "Configurations/systems").glob("*.toml")}
    assert len(systems) == 7
    validators = {
        p.stem.replace("_query", "") for p in (ROOT / "Engines/validation").glob("*_query.py")
    }
    assert validators == {
        "carbon_black_cloud",
        "defender_for_endpoint",
        "sentinel",
        "sentinel_one",
        "splunk",
    }
