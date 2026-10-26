"""`paths.toml` (and legacy `global.toml`): workspace layout and artifact names."""

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


class FrameworkPaths(ConfigurationModel):
    """`[paths.framework]`: legacy location of generated schemas and templates."""

    schemas: str | None = Field(
        default=None, description="Legacy alias of paths.opentide.schemas. " + _PATH
    )
    templates: str | None = Field(
        default=None, description="Legacy alias of paths.opentide.templates. " + _PATH
    )


class LegacyTidePaths(ConfigurationModel):
    """`[paths.tide]`: CoreTIDE-era workspace paths, resolved onto their modern equivalents."""

    threat: str | None = Field(default=None, description="Alias of paths.objects.threat.")
    objective: str | None = Field(default=None, description="Alias of paths.objects.objective.")
    rule: str | None = Field(default=None, description="Alias of paths.objects.rule.")
    analytics: str | None = Field(default=None, description="Unused CoreTIDE analytics folder.")
    snippet_file: str | None = Field(
        default=None, description="Alias of paths.objects.snippet_file."
    )
    json_schemas: str | None = Field(default=None, description="Alias of paths.opentide.schemas.")
    templates: str | None = Field(default=None, description="Alias of paths.opentide.templates.")
    tide_indexes: str | None = Field(default=None, description="Unused CoreTIDE index folder.")
    exports: str | None = Field(default=None, description="Alias of paths.exports.root.")
    custom_configurations: str | None = Field(
        default=None, description="Unused; client configuration lives in .opentide/configurations."
    )


class LegacyCorePaths(ConfigurationModel):
    """`[paths.core]`: CoreTIDE-era framework paths, resolved onto their modern equivalents."""

    staging_index_output: str | None = Field(default=None, description="Unused CoreTIDE path.")
    index_output: str | None = Field(default=None, description="Unused CoreTIDE path.")
    vocabularies: str | None = Field(
        default=None, description="Unused; vocabularies ship in the package."
    )
    configurations: str | None = Field(
        default=None, description="Unused; bundled configuration ships in the package."
    )
    platform_templates: str | None = Field(
        default=None, description="Unused; platform templates ship in the package."
    )
    docs_folder: str | None = Field(default=None, description="Alias of paths.docs.root.")
    rules_docs_folder: str | None = Field(default=None, description="Alias of paths.docs.rules.")
    objectives_docs_folder: str | None = Field(
        default=None, description="Alias of paths.docs.objectives."
    )
    threats_docs_folder: str | None = Field(
        default=None, description="Alias of paths.docs.threats."
    )
    resources: str | None = Field(
        default=None, description="Unused; resources ship in the package."
    )
    log_sources: str | None = Field(
        default=None, description="Unused; log sources ship in the package."
    )


class WorkspacePaths(ConfigurationModel):
    """`[paths]`: workspace directories. Every value is relative to the workspace root."""

    opentide: OpentidePaths | None = Field(default=None, description="The .opentide folder.")
    objects: ObjectPaths | None = Field(default=None, description="Object folders.")
    exports: ExportPaths | None = Field(default=None, description="Exports folder.")
    docs: DocsPaths | None = Field(default=None, description="Documentation folders.")
    framework: FrameworkPaths | None = Field(
        default=None, description="Legacy schema and template folders."
    )
    tide: LegacyTidePaths | None = Field(
        default=None, description="Legacy CoreTIDE workspace paths (paths.tide)."
    )
    core: LegacyCorePaths | None = Field(
        default=None, description="Legacy CoreTIDE framework paths (paths.core)."
    )


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


class LegacyTemplateNames(ConfigurationModel):
    """`[templates]` (global.toml): legacy template file names."""

    threat: str | None = Field(default=None, description="Alias of artifacts.templates.threat.")
    objective: str | None = Field(
        default=None, description="Alias of artifacts.templates.objective."
    )
    rule: str | None = Field(default=None, description="Alias of artifacts.templates.rule.")
    objects: list[ObjectFamily] | None = Field(
        default=None, description="Families a template is generated for."
    )


class LegacyIndexNames(ConfigurationModel):
    """`[indexes]` (global.toml): legacy index file names."""

    revisions: str | None = Field(default=None, description="Revisions index file name.")


class LegacyExportNames(ConfigurationModel):
    """`[exports]` (global.toml): legacy export file names."""

    attack_layer: str | None = Field(
        default=None, description="Alias of artifacts.exports.attack_layer."
    )
    table: str | None = Field(default=None, description="Objects table export file name.")


class Recomposition(ConfigurationModel):
    """`[recomposition]`: where platform sub-schemas are recomposed from."""

    systems: str | None = Field(
        default=None, description="Folder of the platform sub-schemas, under platform templates."
    )


class PathsConfiguration(ConfigurationModel):
    """Merged `paths.toml` or legacy `global.toml`: workspace layout and artifact names."""

    objects: list[ObjectFamily] | None = Field(
        default=None, description="Object families the workspace holds (legacy global.toml)."
    )
    paths: WorkspacePaths | None = Field(default=None, description="Workspace directories.")
    artifacts: Artifacts | None = Field(default=None, description="Generated file names.")
    metaschemas: dict[str, str] | None = Field(
        default=None, description="Model family of each object family, keyed by family."
    )
    recomposition: Recomposition | None = Field(
        default=None, description="Platform sub-schema recomposition."
    )
    indexes: LegacyIndexNames | None = Field(
        default=None, description="Legacy index file names (global.toml)."
    )
    exports: LegacyExportNames | None = Field(
        default=None, description="Legacy export file names (global.toml)."
    )
    json_schemas: dict[str, str] | None = Field(
        default=None, description="Legacy alias of artifacts.schemas (global.toml)."
    )
    templates: LegacyTemplateNames | None = Field(
        default=None, description="Legacy alias of artifacts.templates (global.toml)."
    )
    config_json_schemas: dict[str, str] | None = Field(
        default=None, description="Legacy configuration schema file names (global.toml)."
    )
    config_metaschemas: dict[str, str] | None = Field(
        default=None, description="Legacy configuration metaschema names (global.toml)."
    )
