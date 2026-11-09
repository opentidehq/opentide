"""Write yaml_table.json: what the oracle's YAML loader reads for each case of yaml_cases.toml.

Run it with the oracle's interpreter (opentide 0.23.0, tests/corpora/README.md):

    <oracle python> crates/opentide-schema/tests/oracle/yaml_table.py

It reads each case as `opentide.core.io.load_yaml` reads a file (UTF-8 with an
optional BOM, then `parse_yaml`) and records the value as a tagged tree, or
that the loader refused it. `tests/yaml_table.rs` holds the Rust loader to it.
"""

from __future__ import annotations

import json
import math
import sys
import tomllib
from pathlib import Path
from typing import Any

import yaml

import opentide
from opentide.core.io import parse_yaml

HERE = Path(__file__).resolve().parent


def tagged(value: Any) -> Any:
    """The value as a tree that keeps Python's types (JSON alone would merge some)."""
    if value is None:
        return {"null": None}
    if isinstance(value, bool):
        return {"bool": value}
    if isinstance(value, int):
        return {"int": str(value)}
    if isinstance(value, float):
        if math.isnan(value):
            return {"float": "nan"}
        return {"float": repr(value)}
    if isinstance(value, str):
        return {"str": value}
    if isinstance(value, list):
        return {"seq": [tagged(item) for item in value]}
    if isinstance(value, dict):
        return {"map": [[tagged(key), tagged(item)] for key, item in value.items()]}
    raise TypeError(f"unexpected {type(value).__name__}: {value!r}")


def stable_repr(value: Any) -> str:
    """repr() with sets in sorted order, so the file does not change with the hash seed."""
    if isinstance(value, (set, frozenset)):
        return "{" + ", ".join(sorted(stable_repr(item) for item in value)) + "}"
    if isinstance(value, dict):
        return "{" + ", ".join(f"{stable_repr(k)}: {stable_repr(v)}" for k, v in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ", ".join(stable_repr(item) for item in value) + "]"
    if isinstance(value, tuple):
        return "(" + ", ".join(stable_repr(item) for item in value) + ("," if len(value) == 1 else "") + ")"
    return repr(value)


def read(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return {"error": "not_utf8"}
    try:
        value = parse_yaml(text)
    except yaml.YAMLError as exc:
        return {"error": "yaml", "detail": str(exc).splitlines()[0] if str(exc) else ""}
    except Exception as exc:  # noqa: BLE001 -- recorded: not a YAMLError, the loader lets it escape
        return {"error": "python", "detail": f"{type(exc).__name__}: {exc}"}
    try:
        return {"value": tagged(value)}
    except TypeError:
        # bytes (!!binary), tuples (!!omap, !!pairs), sets (!!set): read by the
        # oracle, refused by the Rust tree (LoadErrorKind::Unsupported).
        return {"unsupported": stable_repr(value)}


def main() -> int:
    cases = tomllib.loads((HERE / "yaml_cases.toml").read_text(encoding="utf-8"))["case"]
    out = []
    for case in cases:
        raw = bytes.fromhex(case["bytes_hex"]) if "bytes_hex" in case else case["yaml"].encode()
        out.append({"id": case["id"], "group": case["group"], **read(raw)})
    document = {
        "oracle": opentide.__version__,
        "pyyaml": yaml.__version__,
        "loader": yaml.CSafeLoader.__name__ if yaml.__with_libyaml__ else "SafeLoader",
        "cases": out,
    }
    (HERE / "yaml_table.json").write_text(
        json.dumps(document, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
