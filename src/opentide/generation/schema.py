"""JSON Schema generation — TideSchemaGenerator entry point."""

from __future__ import annotations

from typing import Any, cast

from pydantic.json_schema import GenerateJsonSchema

from opentide.models.base import TideModel


class TideSchemaGenerator(GenerateJsonSchema):
    """Custom Pydantic JSON Schema generator preserving Tide metadata."""

    def field_title_should_be_set(self, field) -> bool:  # type: ignore[no-untyped-def]
        return True


def model_json_schema(model: type[TideModel]) -> dict[str, Any]:
    """Generate JSON Schema for a TideModel subclass."""
    return cast(dict[str, Any], model.model_json_schema(schema_generator=TideSchemaGenerator))


def run() -> None:
    """Generate JSON schemas from Pydantic-backed pipeline."""
    from opentide.generation.schema_pipeline import run as pipeline_run

    pipeline_run()
