"""JSON Schema generation — TideSchemaGenerator entry point."""

from __future__ import annotations

import json

from opentide.core.files import resolve_configurations
from opentide.core.logging import get_logger
from opentide.generation.configuration_schemas import generate_configuration_schema
from opentide.generation.model_json_schema import TideSchemaGenerator as TideSchemaGenerator
from opentide.generation.model_json_schema import model_json_schema as model_json_schema
from opentide.generation.pydantic_schemas import export_all_registered_schemas
from opentide.generation.router_schema import export_opentide_router
from opentide.registry.paths import resolve_workspace_paths

logger = get_logger(__name__)

__all__ = ["TideSchemaGenerator", "model_json_schema", "run"]


def run() -> None:
    """Generate JSON schemas from Pydantic models into ``.opentide/schemas/``."""
    configs = resolve_configurations()
    paths = resolve_workspace_paths(configs)
    cfg = configs.get("paths") or configs["global"]
    artifacts = cfg.get("artifacts", {})
    schema_map: dict[str, str] = dict(artifacts.get("schemas", cfg.get("json_schemas", {})))
    schema_dir = paths["json_schemas"]
    schema_dir.mkdir(parents=True, exist_ok=True)

    export_all_registered_schemas(json_schema_folder=schema_dir, schema_map=schema_map)

    # model_json_schema() of VisibilityConfig, the same document the configuration
    # export writes: one schema source for visibility.toml (#374).
    visibility_name = schema_map.get("visibility", "visibility.1.0.schema.json")
    visibility_schema = generate_configuration_schema("visibility.toml")
    (schema_dir / visibility_name).write_text(
        json.dumps(visibility_schema, indent=4, sort_keys=False, default=str) + "\n",
        encoding="utf-8",
    )
    logger.info("exported_visibility_schema", path=str(schema_dir / visibility_name))

    router_name = schema_map.get("router", "opentide.schema.json")
    export_opentide_router(schema_dir / router_name)
    logger.info("exported_opentide_router_schema", path=str(schema_dir / router_name))
