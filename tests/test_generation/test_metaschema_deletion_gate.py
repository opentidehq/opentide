"""Guard tests ensuring metaschema YAML sources are fully eliminated."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "opentide"


def test_no_metaschema_yaml_sources() -> None:
    matches = list(SRC.rglob("*.metaschema.yaml"))
    assert matches == [], f"Found metaschema YAML files: {matches}"


def test_no_get_value_metaschema_in_src() -> None:
    result = subprocess.run(
        ["rg", "-n", "get_value_metaschema", str(SRC)],
        capture_output=True,
        text=True,
        check=False,
    )
    lines = [
        line
        for line in result.stdout.splitlines()
        if "replaces get_value_metaschema" not in line and "def get_value_metaschema" not in line
    ]
    assert lines == [], f"get_value_metaschema still referenced:\n{result.stdout}"


def test_no_yaml_metaschema_loading_in_generation() -> None:
    result = subprocess.run(
        ["rg", "-n", r"yaml\.safe_load.*metaschema|METASCHEMAS_FOLDER", str(SRC / "generation")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0 or result.stdout.strip() == "", result.stdout
