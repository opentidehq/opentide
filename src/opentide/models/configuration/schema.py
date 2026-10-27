"""`schema.toml`: template defaults and the retired vocabulary extension table."""

from __future__ import annotations

from pydantic import Field

from opentide.models.configuration.base import ConfigurationModel, OpenConfigurationModel


class VocabularyExtensions(OpenConfigurationModel):
    """`[vocabulary]`: CoreTIDE-era vocabulary extensions.

    Vocabularies are canonical upstream and are not extended locally since
    0.13.0. The table stays open so a file that still carries one loads; its
    contents are ignored.
    """


class SchemaConfiguration(ConfigurationModel):
    """Merged `schema.toml`: defaults inserted into generated templates."""

    templates: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Template text keyed by scoped field path, for example "
            '"rule::response::procedure::analysis".'
        ),
    )
    vocabulary: VocabularyExtensions | None = Field(
        default=None,
        description="Retired vocabulary extensions. Accepted and ignored.",
    )
