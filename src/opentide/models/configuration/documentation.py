"""`documentation.toml`: settings for `opentide generate docs`."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BeforeValidator, Field, Strict, WithJsonSchema

from opentide.documentation.types import DocumentFlavor
from opentide.models.configuration.base import ConfigurationModel, ObjectFamily

#: A flavor written by name (`default = "gitlab"`). `azure-devops` is read as
#: `azure_devops`, as `--flavor` does, and the schema accepts it too.
FlavorName = Annotated[
    DocumentFlavor,
    Strict(False),
    BeforeValidator(lambda value: value.replace("-", "_") if isinstance(value, str) else value),
    WithJsonSchema(
        {
            "type": "string",
            "anyOf": [
                {"enum": [flavor.value for flavor in DocumentFlavor]},
                {"const": "azure-devops"},
            ],
            "description": "Markdown flavor: github, gitlab, azure_devops or generic.",
        }
    ),
]


class FlavorSettings(ConfigurationModel):
    """`[flavor]`: which markdown dialect the documentation is written for."""

    default: FlavorName = Field(
        default=DocumentFlavor.generic,
        description="Markdown flavor used when opentide generate docs gets no --flavor.",
    )


class GitlabSettings(ConfigurationModel):
    """`[gitlab]`: settings that apply to the gitlab flavor only."""

    uuid_permalinks: bool = Field(
        default=False, description="Link object pages by UUID instead of by name (gitlab only)."
    )


class DiagramSettings(ConfigurationModel):
    """`[diagrams]`: relation diagrams drawn on object pages."""

    relations_direction: Literal["upstream", "downstream", "both"] = Field(
        default="both", description="Which relations an object page diagram draws."
    )


class IndexSettings(ConfigurationModel):
    """`[index]`: the generated index pages."""

    relation_counts: bool = Field(
        default=True, description="Show how many objects each object relates to."
    )
    icons: bool = Field(default=False, description="Prefix index entries with the family icon.")


class CveSettings(ConfigurationModel):
    """`[cve]`: the Vulnerability-Lookup instance CVE references resolve against."""

    base_url: str = Field(
        default="https://vulnerability.circl.lu",
        description="Base URL of the Vulnerability-Lookup API.",
    )
    default_db_link: str = Field(
        default="", description="Prefix of the page a CVE reference links to."
    )
    retrieve_details: bool = Field(
        default=True, description="Fetch CVE details while generating documentation."
    )
    timeout: float = Field(default=15.0, gt=0, description="Lookup timeout in seconds.")


class ObjectNames(ConfigurationModel):
    """`[object_names]`: display names of each object family."""

    threat: str | None = Field(default=None, description="Display name of threat vectors.")
    objective: str | None = Field(default=None, description="Display name of detection objectives.")
    signal: str | None = Field(
        default=None, description="Display name of detection objective signals."
    )
    rule: str | None = Field(default=None, description="Display name of detection rules.")


class DocumentationConfiguration(ConfigurationModel):
    """Merged `documentation.toml`: what `opentide generate docs` writes and how."""

    scope: list[ObjectFamily] = Field(
        default=["threat", "objective", "rule"],
        description="Object families that get documentation pages.",
    )
    skip_model_keys: list[str] = Field(
        default_factory=list, description="Object keys left out of the rendered pages."
    )
    folder_index_pages: bool = Field(
        default=True, description="Write an index page in every documentation folder."
    )
    output: str | None = Field(
        default=None,
        description="Output folder, relative to the repository. Defaults to the docs path.",
    )
    flavor: FlavorName | FlavorSettings = Field(
        default_factory=FlavorSettings,
        description="Markdown flavor: a [flavor] table, or the flavor name itself.",
    )
    gitlab: GitlabSettings = Field(
        default_factory=GitlabSettings, description="Settings for the gitlab flavor."
    )
    diagrams: DiagramSettings = Field(
        default_factory=DiagramSettings, description="Relation diagrams."
    )
    index: IndexSettings = Field(default_factory=IndexSettings, description="Index pages.")
    cve: CveSettings = Field(default_factory=CveSettings, description="CVE lookups.")
    object_names: ObjectNames = Field(
        default_factory=ObjectNames, description="Display names of each object family."
    )
    icons: dict[str, str] = Field(
        default_factory=dict, description="Icon shown for each object family, keyed by family."
    )

    def default_flavor(self) -> DocumentFlavor:
        if isinstance(self.flavor, FlavorSettings):
            return self.flavor.default
        return self.flavor
