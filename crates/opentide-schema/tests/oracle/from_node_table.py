"""Write from_node_table.json: what Pydantic and the CLI report for each case of from_node_cases.toml.

Run it with the oracle's interpreter (opentide 0.23.0, tests/corpora/README.md):

    <oracle python> crates/opentide-schema/tests/oracle/from_node_table.py

Each case is a YAML document and the model it is checked against. The models
below are Pydantic models built the way the oracle builds its own (TideModel:
extra="forbid", populate_by_name), with one field of each type and convention
the Rust conversion supports; `tests/from_node_table.rs` declares the same
models in Rust with `#[derive(FromNode)]`. For each case the script records
what the oracle's pipeline would print for an object file:

- every Pydantic error: `type`, `loc` (as the CLI's `field_path`), `msg`, the
  input when it is a string, and `ctx`;
- where the CLI points for it: `SourceFiles.span` (line, column, end_column),
  with `at_key` for "Extra inputs are not permitted" as the CLI passes it, and
  the `yaml_line` `attach_yaml_lines` gives it (`_find_line`);
- or, when the document validates, the model's `model_dump(by_alias=True)`.
"""

from __future__ import annotations

import json
import math
import sys
import tempfile
import tomllib
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, ValidationError, ValidationInfo, field_validator, model_validator
from pydantic_core import PydanticCustomError

import opentide
from opentide.cli.ui.diagnostics import SourceFiles
from opentide.core.io import parse_yaml
from opentide.models.base import TideModel
from opentide.validation.errors import _find_line, load_yaml_with_lines

HERE = Path(__file__).resolve().parent


class Kind(str, Enum):
    ALPHA = "alpha"
    BETA = "beta"
    GAMMA = "gamma"


class Inner(TideModel):
    label: str
    count: int | None = None


class Probe(TideModel):
    """One field per type and convention of the conversion."""

    text: str
    number: int = 0
    ratio: float | None = None
    flag: bool = True
    items: list[str] | None = None
    inners: list[Inner] | None = None
    inner: Inner | None = None
    mapping: dict[str, int] | None = None
    choice: Literal["one", "two"] | None = None
    kind: Kind | None = None
    either: str | int | None = None
    some: str | list[str] | None = None
    schema_id: str | None = Field(default=None, alias="schema")
    vocab: list[str] | None = None

    @field_validator("vocab", mode="before")
    @classmethod
    def _require_vocab_list(cls, value: Any, info: ValidationInfo) -> Any:
        # As ThreatBody._require_vocab_list (models/threat.py).
        if isinstance(value, str):
            message = "must be a YAML list of {field} vocabulary names, not a single string"
            if ";" in value:
                message += "; list each name in '{value}' as its own item"
            raise PydanticCustomError(
                "vocab_list_type", message, {"field": info.field_name, "value": value}
            )
        return value


class Guarded(TideModel):
    """A model with a `mode="before"` model validator that refuses a key."""

    name: str
    other: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _no_legacy(cls, data: Any) -> Any:
        if isinstance(data, dict) and "legacy" in data:
            raise ValueError("legacy is not supported")
        return data


class SampleExample(TideModel):
    description: str
    link: str
    language: str | None = None


class SampleV1_1(TideModel):
    """crates/opentide-schema/src/sample.rs, revision 1.1, as Pydantic."""

    name: str
    uuid: str
    schema_id: str = Field(alias="schema")
    description: str
    severity: str
    effort: int | None = None
    enabled: bool = True
    examples: list[SampleExample] | None = None
    tags: list[str] = Field(default_factory=list)


MODELS = {"Probe": Probe, "Guarded": Guarded, "SampleV1_1": SampleV1_1}


def plain(value: Any) -> Any:
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return repr(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): plain(item) for key, item in value.items()}
    if isinstance(value, list):
        return [plain(item) for item in value]
    return value


def find_line(located: Any, field_path: list[str]) -> Any:
    """`_find_line`, or the exception it raises (it reads ruamel's markers
    without a guard, and a merged key has none: the oracle crashes there)."""
    if located is None:
        return None
    try:
        return _find_line(located, tuple(field_path))
    except Exception as exc:  # noqa: BLE001 -- recorded as data: the oracle's own crash
        return {"crash": type(exc).__name__}


def run(model: type[TideModel], text: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "object.yaml"
        path.write_text(text, encoding="utf-8")
        body = parse_yaml(text)
        try:
            value = model.model_validate(body)
        except ValidationError as exc:
            sources = SourceFiles()
            located = load_yaml_with_lines(path)
            errors = []
            for err in exc.errors():
                field_path = [str(part) for part in err["loc"]]
                at_key = err["msg"].startswith("Extra inputs are not permitted")
                span = sources.span(path, field_path, at_key=at_key)
                ctx = {key: str(item) for key, item in (err.get("ctx") or {}).items()}
                errors.append(
                    {
                        "type": err["type"],
                        "field_path": field_path,
                        "msg": err["msg"],
                        "input": err["input"] if isinstance(err["input"], str) else None,
                        "ctx": ctx,
                        "span": None
                        if span is None
                        else [span.line, span.column, span.end_column, span.found],
                        "yaml_line": find_line(located, field_path),
                    }
                )
            return {"errors": errors}
    return {"value": plain(value.model_dump(by_alias=True))}


def main() -> int:
    cases = tomllib.loads((HERE / "from_node_cases.toml").read_text(encoding="utf-8"))["case"]
    out = []
    for case in cases:
        out.append({"id": case["id"], "model": case["model"], "yaml": case["yaml"],
                    **run(MODELS[case["model"]], case["yaml"])})
    document = {"oracle": opentide.__version__, "cases": out}
    (HERE / "from_node_table.json").write_text(
        json.dumps(document, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
