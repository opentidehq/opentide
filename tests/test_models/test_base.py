"""TideModel and TideField base behaviour."""

from __future__ import annotations

from pydantic import Field
from pydantic.fields import FieldInfo

from opentide.models.base import TideField, TideModel, field_json_schema_extra


def test_tide_field_attaches_schema_extra() -> None:
    field = TideField("x", schema_extra={"tide.vocab": True})
    assert isinstance(field, FieldInfo)


class _ExampleModel(TideModel):
    __schema_identifier__ = "example::1.0"
    name: str


def test_tide_model_schema_identifier() -> None:
    assert _ExampleModel.schema_identifier() == "example::1.0"


def test_field_json_schema_extra_reads_metadata() -> None:
    class M(TideModel):
        label: str = Field(json_schema_extra={"tide.template.hide": True})

    info = M.model_fields["label"]
    assert field_json_schema_extra(info)["tide.template.hide"] is True
