"""Guard tests ensuring metaschema YAML sources are fully eliminated."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "opentide"
GENERATION = SRC / "generation"


def _iter_python_sources(directory: Path) -> list[Path]:
    return sorted(directory.rglob("*.py"))


def _scan_sources(
    directory: Path,
    *,
    needle: str,
    skip_substrings: tuple[str, ...] = (),
) -> list[str]:
    matches: list[str] = []
    for path in _iter_python_sources(directory):
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if needle not in line:
                continue
            if any(skip in line for skip in skip_substrings):
                continue
            matches.append(f"{path.relative_to(ROOT)}:{line_number}:{line.strip()}")
    return matches


def test_no_metaschema_yaml_sources() -> None:
    matches = list(SRC.rglob("*.metaschema.yaml"))
    assert matches == [], f"Found metaschema YAML files: {matches}"


def test_no_get_value_metaschema_in_src() -> None:
    lines = _scan_sources(
        SRC,
        needle="get_value_metaschema",
        skip_substrings=("replaces get_value_metaschema", "def get_value_metaschema"),
    )
    assert lines == [], "get_value_metaschema still referenced:\n" + "\n".join(lines)


def test_no_yaml_metaschema_loading_in_generation() -> None:
    lines: list[str] = []
    for path in _iter_python_sources(GENERATION):
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if "METASCHEMAS_FOLDER" in line or ("yaml.safe_load" in line and "metaschema" in line):
                lines.append(f"{path.relative_to(ROOT)}:{line_number}:{line.strip()}")
    assert lines == [], "yaml/metaschema loading still present in generation:\n" + "\n".join(lines)
