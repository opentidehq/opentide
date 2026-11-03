"""`paths.toml`: workspace layout and artifact names."""

from __future__ import annotations

from pydantic import Field

from opentide.models.configuration.base import ConfigurationModel, ObjectFamily

_PATH = "Path relative to the workspace root."


class OpentidePaths(ConfigurationModel):
    """`[paths.opentide]`: the `.opentide/` folder and its generated artifacts."""

    root: str | None = Field(default=None, description="The .opentide folder. " + _PATH)
    schemas: str | None = Field(default=None, description="Generated JSON Schemas. " + _PATH)
    templates: str | None = Field(default=None, description="Generated templates. " + _PATH)


class ObjectPaths(ConfigurationModel):
    """`[paths.objects]`: where each object family is authored."""

    threat: str | None = Field(default=None, description="Threat vector folder. " + _PATH)
    objective: str | None = Field(default=None, description="Detection objective folder. " + _PATH)
    rule: str | None = Field(default=None, description="Detection rule folder. " + _PATH)
    snippet_file: str | None = Field(
        default=None, description="Generated VS Code snippet file. " + _PATH
    )


class ExportPaths(ConfigurationModel):
    """`[paths.exports]`: where `opentide generate exports` writes."""

    root: str | None = Field(default=None, description="Exports folder. " + _PATH)


class DocsPaths(ConfigurationModel):
    """`[paths.docs]`: where `opentide generate docs` writes each family."""

    root: str | None = Field(default=None, description="Documentation root. " + _PATH)
    rules: str | None = Field(default=None, description="Rule pages. " + _PATH)
    objectives: str | None = Field(default=None, description="Objective pages. " + _PATH)
    threats: str | None = Field(default=None, description="Threat pages. " + _PATH)


class WorkspacePaths(ConfigurationModel):
    """`[paths]`: workspace directories. Every value is relative to the workspace root."""

    opentide: OpentidePaths | None = Field(default=None, description="The .opentide folder.")
    objects: ObjectPaths | None = Field(default=None, description="Object folders.")
    exports: ExportPaths | None = Field(default=None, description="Exports folder.")
    docs: DocsPaths | None = Field(default=None, description="Documentation folders.")


class SchemaArtifacts(ConfigurationModel):
    """`[artifacts.schemas]`: file names of the generated JSON Schemas."""

    threat: str | None = Field(default=None, description="Threat vector schema file name.")
    objective: str | None = Field(default=None, description="Detection objective schema file name.")
    rule: str | None = Field(default=None, description="Detection rule schema file name.")
    visibility: str | None = Field(default=None, description="visibility.toml schema file name.")
    router: str | None = Field(default=None, description="Object router schema file name.")


class TemplateArtifacts(ConfigurationModel):
    """`[artifacts.templates]`: file names of the generated templates."""

    threat: str | None = Field(default=None, description="Threat vector template file name.")
    objective: str | None = Field(
        default=None, description="Detection objective template file name."
    )
    rule: str | None = Field(default=None, description="Detection rule template file name.")


class ExportArtifacts(ConfigurationModel):
    """`[artifacts.exports]`: file names of the generated exports."""

    revisions: str | None = Field(default=None, description="Revisions export file name.")
    objects: str | None = Field(default=None, description="Objects export file name.")
    attack_layer: str | None = Field(default=None, description="ATT&CK Navigator layer file name.")


class Artifacts(ConfigurationModel):
    """`[artifacts]`: file names of everything opentide generates."""

    schemas: SchemaArtifacts | None = Field(default=None, description="JSON Schema files.")
    templates: TemplateArtifacts | None = Field(default=None, description="Template files.")
    exports: ExportArtifacts | None = Field(default=None, description="Export files.")


class PathsConfiguration(ConfigurationModel):
    """Merged `paths.toml`: workspace layout and artifact names."""

    objects: list[ObjectFamily] | None = Field(
        default=None, description="Object families the workspace holds."
    )
    paths: WorkspacePaths | None = Field(default=None, description="Workspace directories.")
    artifacts: Artifacts | None = Field(default=None, description="Generated file names.")
    metaschemas: dict[str, str] | None = Field(
        default=None, description="Model family of each object family, keyed by family."
    )
