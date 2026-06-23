"""Backward-compatible shim — implementation lives in opentide.generation.schema_pipeline."""

from opentide.generation.schema_pipeline import (  # noqa: F401
    VocabularyResolver,
    gen_json_schema,
    recomposition_handler,
    run,
    strip_framework_keywords,
)
