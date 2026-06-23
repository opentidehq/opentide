#!/usr/bin/env python3
"""One-shot migration: absorb src/Engines into src/opentide."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENGINES = ROOT / "src" / "Engines"
OPENTIDE = ROOT / "src" / "opentide"

PLATFORM_DEPLOY = {
    "splunk": "splunk",
    "sentinel": "sentinel",
    "sentinel_one": "sentinel_one",
    "defender_for_endpoint": "defender_for_endpoint",
    "crowdstrike": "crowdstrike",
    "harfanglab": "harfanglab",
    "carbon_black_cloud": "carbon_black",
}

PLATFORM_VALIDATOR = {
    "splunk_query": "splunk",
    "sentinel_query": "sentinel",
    "sentinel_one_query": "sentinel_one",
    "defender_for_endpoint_query": "defender_for_endpoint",
    "carbon_black_cloud_query": "carbon_black",
}

PLATFORM_CLIENT = {
    "splunk": "splunk",
    "sentinel": "sentinel",
    "sentinel_one": "sentinel_one",
    "defender_for_endpoint": "defender_for_endpoint",
    "crowdstrike": "crowdstrike",
    "harfanglab": "harfanglab",
    "carbon_black_cloud": "carbon_black",
}

# Longest patterns first for safe replacement.
IMPORT_REWRITES: list[tuple[str, str]] = [
    ("opentide.loading.config_loader", "opentide.loading.config_loader"),
    ("opentide.loading.compat", "opentide.loading.compat"),
    ("opentide.loading.platform_loader", "opentide.loading.platform_loader"),
    ("opentide.platforms.carbon_black.client", "opentide.platforms.carbon_black.client"),
    ("opentide.platforms.defender_for_endpoint.client", "opentide.platforms.defender_for_endpoint.client"),
    ("opentide.platforms.sentinel_one.client", "opentide.platforms.sentinel_one.client"),
    ("opentide.platforms.crowdstrike.client", "opentide.platforms.crowdstrike.client"),
    ("opentide.platforms.harfanglab.client", "opentide.platforms.harfanglab.client"),
    ("opentide.platforms.sentinel.client", "opentide.platforms.sentinel.client"),
    ("opentide.platforms.splunk.client", "opentide.platforms.splunk.client"),
    ("opentide.platforms.kql", "opentide.platforms.kql"),
    ("opentide.loading.configurations", "opentide.loading.configurations"),
    ("opentide.loading.objects", "opentide.loading.objects"),
    ("opentide.deployment.planning", "opentide.deployment.planning"),
    ("opentide.deployment.utils", "opentide.deployment.utils"),
    ("opentide.documentation.components", "opentide.documentation.components"),
    ("opentide.platforms.carbon_black.client", "opentide.platforms.carbon_black.client"),
    ("opentide.models.config_models", "opentide.models.config_models"),
    ("opentide.models.object_models", "opentide.models.object_models"),
    ("opentide.models.system_models", "opentide.models.system_models"),
    ("opentide.platforms.carbon_black.deployer", "opentide.platforms.carbon_black.deployer"),
    ("opentide.platforms.defender_for_endpoint.deployer", "opentide.platforms.defender_for_endpoint.deployer"),
    ("opentide.platforms.sentinel_one.deployer", "opentide.platforms.sentinel_one.deployer"),
    ("opentide.platforms.crowdstrike.deployer", "opentide.platforms.crowdstrike.deployer"),
    ("opentide.platforms.harfanglab.deployer", "opentide.platforms.harfanglab.deployer"),
    ("opentide.platforms.sentinel.deployer", "opentide.platforms.sentinel.deployer"),
    ("opentide.platforms.splunk.deployer", "opentide.platforms.splunk.deployer"),
    ("opentide.platforms.carbon_black.validator", "opentide.platforms.carbon_black.validator"),
    ("opentide.platforms.defender_for_endpoint.validator", "opentide.platforms.defender_for_endpoint.validator"),
    ("opentide.platforms.sentinel_one.validator", "opentide.platforms.sentinel_one.validator"),
    ("opentide.platforms.sentinel.validator", "opentide.platforms.sentinel.validator"),
    ("opentide.platforms.splunk.validator", "opentide.platforms.splunk.validator"),
    ("opentide.validation.id_uniqueness", "opentide.validation.id_uniqueness"),
    ("opentide.validation.tide_schema", "opentide.validation.tide_schema"),
    ("opentide.validation.uuid_v4", "opentide.validation.uuid_v4"),
    ("opentide.generation.vscode_snippets", "opentide.generation.vscode_snippets"),
    ("opentide.generation.schema_pipeline", "opentide.generation.schema_pipeline"),
    ("opentide.generation.template_renderer", "opentide.generation.template_renderer"),
    ("opentide.export.attack_navigator_layer", "opentide.export.attack_navigator_layer"),
    ("opentide.export.table_export", "opentide.export.table_export"),
    ("opentide.indexing.staging_indexer", "opentide.indexing.staging_indexer"),
    ("opentide.export.playbook_map", "opentide.export.playbook_map"),
    ("opentide.indexing.object_vocab", "opentide.indexing.object_vocab"),
    ("opentide.indexing.revisions", "opentide.indexing.revisions"),
    ("opentide.indexing.indexer", "opentide.indexing.indexer"),
    ("opentide.mutation.promotion", "opentide.mutation.promotion"),
    ("opentide.mutation.security_domain", "opentide.mutation.security_domain"),
    ("opentide.mutation.references", "opentide.mutation.references"),
    ("opentide.mutation.file_name", "opentide.mutation.file_name"),
    ("opentide.documentation.templates.models", "opentide.documentation.templates.models"),
    ("opentide.documentation.templates.mdr", "opentide.documentation.templates.mdr"),
    ("opentide.documentation.templates.dom", "opentide.documentation.templates.dom"),
    ("opentide.documentation.wiki_navigation", "opentide.documentation.wiki_navigation"),
    ("opentide.documentation.vocabularies", "opentide.documentation.vocabularies"),
    ("opentide.documentation.metaschemas", "opentide.documentation.metaschemas"),
    ("opentide.documentation.models", "opentide.documentation.models"),
    ("opentide.documentation.dom", "opentide.documentation.dom"),
    ("opentide.documentation.mdr", "opentide.documentation.mdr"),
    ("opentide.extraction.d3fend_countermeasures", "opentide.extraction.d3fend_countermeasures"),
    ("opentide.extraction.d3fend_artifacts", "opentide.extraction.d3fend_artifacts"),
    ("opentide.extraction.sentinel_importer", "opentide.extraction.sentinel_importer"),
    ("opentide.extraction.mde_importer", "opentide.extraction.mde_importer"),
    ("opentide.extraction.threat_actors", "opentide.extraction.threat_actors"),
    ("opentide.extraction.atc_react", "opentide.extraction.atc_react"),
    ("opentide.extraction.malapi", "opentide.extraction.malapi"),
    ("opentide.extraction.engage", "opentide.extraction.engage"),
    ("opentide.extraction.attack", "opentide.extraction.attack"),
    ("opentide.extraction.nist", "opentide.extraction.nist"),
    ("opentide.core.typing", "opentide.core.typing"),
    ("opentide.core.environment", "opentide.core.environment"),
    ("opentide.documentation.core", "opentide.documentation.core"),
    ("opentide.deployment", "opentide.deployment"),
    ("opentide.generation.framework", "opentide.generation.framework"),
    ("opentide.generation.vocabulary", "opentide.generation.vocabulary"),
    ("opentide.validation.legacy", "opentide.validation.legacy"),
    ("opentide.deployment.git_repo", "opentide.deployment.git_repo"),
    ("opentide.platforms.plugins", "opentide.platforms.plugins"),
    ("opentide.platforms.plugins", "opentide.platforms.plugins"),
    ("opentide.core.registry", "opentide.core.registry"),
    ("opentide.platforms.splunk.client", "opentide.platforms.splunk.client"),
    ("opentide.documentation.graphs", "opentide.documentation.graphs"),
    ("opentide.core.index_legacy", "opentide.core.index_legacy"),
    ("opentide.core.errors", "opentide.core.errors"),
    ("opentide.core.debug", "opentide.core.debug"),
    ("opentide.models.legacy", "opentide.models.legacy"),
    ("opentide.models.deployment_enums", "opentide.models.deployment_enums"),
    ("opentide.core.files", "opentide.core.files"),
    ("opentide.core.logging", "opentide.core.logging"),
    ("opentide.core.registry", "opentide.core.registry"),
    ("opentide.deployment.ci", "opentide.deployment.ci"),
    ("opentide.validation.cve", "opentide.validation.cve"),
    ("opentide.mutation", "opentide.mutation"),
    ("opentide.export", "opentide.export"),
    ("opentide.extraction", "opentide.extraction"),
    ("opentide.documentation", "opentide.documentation"),
    ("opentide.generation", "opentide.generation"),
    ("opentide.indexing", "opentide.indexing"),
    ("opentide.platforms", "opentide.platforms"),
    ("opentide.validation", "opentide.validation"),
    ("opentide.documentation.templates", "opentide.documentation.templates"),
    ("opentide.core", "opentide.core"),
]


def copy_file(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def rewrite_imports(text: str) -> str:
    for old, new in IMPORT_REWRITES:
        text = text.replace(old, new)
    # Remove git.Repo sys.path bootstrapping
    text = re.sub(
        r"^import git\n",
        "",
        text,
        flags=re.MULTILINE,
    )
    text = re.sub(
        r"^sys\.path\.append\(str\(git\.Repo\([^)]*\)[^)]*\)\)\n",
        "",
        text,
        flags=re.MULTILINE,
    )
    text = re.sub(
        r"^from git import Repo\n",
        "",
        text,
        flags=re.MULTILINE,
    )
    return text


def write_rewritten(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(rewrite_imports(src.read_text(encoding="utf-8")), encoding="utf-8")


def move_platforms() -> None:
    for src_name, pkg in PLATFORM_DEPLOY.items():
        write_rewritten(
            ENGINES / "deployment" / f"{src_name}.py",
            OPENTIDE / "platforms" / pkg / "deployer.py",
        )
        (OPENTIDE / "platforms" / pkg / "__init__.py").write_text(
            f'"""{pkg.replace("_", " ").title()} platform."""\n\n'
            f"from opentide.platforms.{pkg}.deployer import declare\n\n"
            f"__all__ = [\"declare\"]\n",
            encoding="utf-8",
        )
    for src_name, pkg in PLATFORM_VALIDATOR.items():
        write_rewritten(
            ENGINES / "validation" / f"{src_name}.py",
            OPENTIDE / "platforms" / pkg / "validator.py",
        )
    for src_name, pkg in PLATFORM_CLIENT.items():
        write_rewritten(
            ENGINES / "modules" / "systems" / f"{src_name}.py",
            OPENTIDE / "platforms" / pkg / "client.py",
        )
    write_rewritten(
        ENGINES / "modules" / "systems" / "kql.py",
        OPENTIDE / "platforms" / "kql.py",
    )


def move_packages() -> None:
    for name in ("uuid_v4", "cve", "id_uniqueness", "tide_schema"):
        write_rewritten(ENGINES / "validation" / f"{name}.py", OPENTIDE / "validation" / f"{name}.py")

    for name in ("file_name", "references", "security_domain", "promotion"):
        write_rewritten(ENGINES / "mutation" / f"{name}.py", OPENTIDE / "mutation" / f"{name}.py")
    (OPENTIDE / "mutation" / "__init__.py").write_text(
        '"""MDR mutation helpers."""\n', encoding="utf-8"
    )

    for name in ("attack_navigator_layer", "table_export"):
        write_rewritten(ENGINES / "export" / f"{name}.py", OPENTIDE / "export" / f"{name}.py")

    for path in sorted((ENGINES / "extraction").glob("*.py")):
        if path.name == "__init__.py":
            continue
        write_rewritten(path, OPENTIDE / "extraction" / path.name)
    (OPENTIDE / "extraction" / "__init__.py").write_text(
        '"""External data extraction pipelines."""\n', encoding="utf-8"
    )

    for name in ("indexer", "staging_indexer", "revisions"):
        write_rewritten(ENGINES / "indexing" / f"{name}.py", OPENTIDE / "indexing" / f"{name}.py")

    write_rewritten(
        ENGINES / "framework" / "vscode_snippets.py",
        OPENTIDE / "generation" / "vscode_snippets.py",
    )

    for name in ("dom", "mdr", "metaschemas", "models", "vocabularies", "wiki_navigation"):
        write_rewritten(
            ENGINES / "documentation" / f"{name}.py",
            OPENTIDE / "documentation" / f"{name}.py",
        )
    for name in ("dom", "mdr", "models"):
        write_rewritten(
            ENGINES / "templates" / f"{name}.py",
            OPENTIDE / "documentation" / "templates" / f"{name}.py",
        )
    (OPENTIDE / "documentation" / "templates" / "__init__.py").write_text(
        '"""Markdown documentation templates."""\n', encoding="utf-8"
    )


def move_core_modules() -> None:
    mappings = {
        "errors.py": OPENTIDE / "core" / "errors.py",
        "debug.py": OPENTIDE / "core" / "debug.py",
        "environment.py": OPENTIDE / "core" / "environment.py",
        "_typing.py": OPENTIDE / "core" / "typing.py",
        "framework.py": OPENTIDE / "generation" / "framework.py",
        "vocabulary.py": OPENTIDE / "generation" / "vocabulary.py",
        "validation.py": OPENTIDE / "validation" / "legacy.py",
        "documentation.py": OPENTIDE / "documentation" / "core.py",
        "documentation_components.py": OPENTIDE / "documentation" / "components.py",
        "graphs.py": OPENTIDE / "documentation" / "graphs.py",
        "deployment.py": OPENTIDE / "deployment" / "__init__.py",
        "deployment_planning.py": OPENTIDE / "deployment" / "planning.py",
        "deployment_utils.py": OPENTIDE / "deployment" / "utils.py",
        "ci.py": OPENTIDE / "deployment" / "ci.py",
        "git_repo.py": OPENTIDE / "deployment" / "git_repo.py",
        "enums.py": OPENTIDE / "models" / "deployment_enums.py",
        "config_models.py": OPENTIDE / "models" / "config_models.py",
        "object_models.py": OPENTIDE / "models" / "object_models.py",
        "system_models.py": OPENTIDE / "models" / "system_models.py",
        "platforms.py": OPENTIDE / "platforms" / "plugins.py",
        "index.py": OPENTIDE / "core" / "index_legacy.py",
    }
    for src_name, dst in mappings.items():
        write_rewritten(ENGINES / "modules" / src_name, dst)

    write_rewritten(
        ENGINES / "modules" / "loaders" / "config_loader.py",
        OPENTIDE / "loading" / "config_loader.py",
    )
    write_rewritten(
        ENGINES / "modules" / "datamodels" / "objects.py",
        OPENTIDE / "loading" / "objects.py",
    )
    write_rewritten(
        ENGINES / "modules" / "datamodels" / "configurations.py",
        OPENTIDE / "loading" / "configurations.py",
    )

    # Legacy models aggregator shim
    (OPENTIDE / "models" / "legacy.py").write_text(
        '''"""Backward-compatible model re-exports."""

from opentide.models.deployment_enums import (
    DeploymentStrategy,
    DetectionPlatforms,
    StatusStrategy,
)
from opentide.models.config_models import ConfigurationModels
from opentide.models.object_models import SharedModels, TideModels, DetectionRule, ThreatVector
from opentide.models.system_models import DeploymentBatch, SystemConfig, TenantDeployment

DetectionSystems = DetectionPlatforms
TenantDeploymentModel = DeploymentBatch
TideConfigs = ConfigurationModels
ObjectMetadata = SharedModels.ObjectMetadata
ObjectReferences = SharedModels.ObjectReferences
PlatformConfigurationBase = SharedModels.PlatformConfigurationBase
TideDefinitionsModels = SharedModels

__all__ = [
    "StatusStrategy",
    "DetectionPlatforms",
    "DetectionSystems",
    "DeploymentStrategy",
    "SystemConfig",
    "ConfigurationModels",
    "TideConfigs",
    "SharedModels",
    "TideDefinitionsModels",
    "TideModels",
    "DetectionRule",
    "ThreatVector",
    "ObjectMetadata",
    "ObjectReferences",
    "PlatformConfigurationBase",
    "DeploymentBatch",
    "TenantDeploymentModel",
    "TenantDeployment",
]
''',
        encoding="utf-8",
    )


def update_platform_shims() -> None:
    for pkg in set(PLATFORM_DEPLOY.values()):
        shim = OPENTIDE / "platforms" / f"{pkg}.py"
        if shim.is_file():
            shim.write_text(
                f'"""{pkg.replace("_", " ").title()} platform plugin."""\n\n'
                f"from opentide.platforms.{pkg}.deployer import declare\n\n"
                f"__all__ = [\"declare\"]\n",
                encoding="utf-8",
            )


def rewrite_tree(directory: Path) -> None:
    for path in directory.rglob("*.py"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        new_text = rewrite_imports(text)
        if new_text != text:
            path.write_text(new_text, encoding="utf-8")


def rewrite_tests_and_scripts() -> None:
    for directory in (ROOT / "tests", ROOT / "scripts"):
        if directory.is_dir():
            rewrite_tree(directory)


def remove_engines() -> None:
    if ENGINES.is_dir():
        shutil.rmtree(ENGINES)


def main() -> None:
    move_platforms()
    move_packages()
    move_core_modules()
    update_platform_shims()
    rewrite_tree(OPENTIDE)
    rewrite_tests_and_scripts()
    remove_engines()
    print("Engines absorption complete.")


if __name__ == "__main__":
    main()
