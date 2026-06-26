"""Vocabulary pin manifest loader (per schema revision)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from opentide.core.io import load_toml
from opentide.models.version import SchemaVersion

_PINS_DIR = Path(__file__).resolve().parent.parent / "data" / "pins"
_PIN_FAMILIES = ("threat", "objective", "rule")


@lru_cache
def _load_family_pins(family: str) -> dict[str, dict[str, str]]:
    path = _PINS_DIR / f"{family}.toml"
    if not path.is_file():
        return {}
    raw = load_toml(path)
    if not isinstance(raw, dict):
        return {}
    result: dict[str, dict[str, str]] = {}
    for section, pins in raw.items():
        if not isinstance(pins, dict):
            continue
        result[str(section)] = {str(key): str(value) for key, value in pins.items()}
    return result


@lru_cache
def _load_all_pins() -> dict[str, dict[str, str]]:
    merged: dict[str, dict[str, str]] = {}
    for family in _PIN_FAMILIES:
        merged.update(_load_family_pins(family))
    return merged


def get_pins(schema_id: str) -> dict[str, str]:
    """Return dot-path → ``field::M.m`` pins for a registered schema identifier."""
    return dict(_load_all_pins().get(schema_id, {}))


def pins_for_family(family: str) -> dict[str, dict[str, str]]:
    """Return all pin sections declared for an object family."""
    return {
        schema_id: pins
        for schema_id, pins in _load_all_pins().items()
        if SchemaVersion.parse(schema_id).family == family.lower()
    }


def clear_pin_cache() -> None:
    """Clear cached pin manifests (tests)."""
    _load_family_pins.cache_clear()
    _load_all_pins.cache_clear()


def pin_data_dir() -> Path:
    """Bundled pin manifest directory."""
    return _PINS_DIR


def load_pin_file(path: Path) -> dict[str, Any]:
    """Load a single pin TOML file (tests, sync tooling)."""
    return load_toml(path)
