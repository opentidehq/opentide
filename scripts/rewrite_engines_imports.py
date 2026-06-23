#!/usr/bin/env python3
"""Rewrite remaining Engines.* imports under src/opentide."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OPENTIDE = ROOT / "src" / "opentide"

IMPORT_REWRITES: list[tuple[str, str]] = [
    ("Engines.modules.loaders.config_loader", "opentide.loading.config_loader"),
    ("Engines.modules.loaders.object_loader", "opentide.loading.compat"),
    ("Engines.modules.loaders.system_loader", "opentide.loading.platform_loader"),
    ("Engines.modules.systems.carbon_black_cloud", "opentide.platforms.carbon_black.client"),
    ("Engines.modules.systems.defender_for_endpoint", "opentide.platforms.defender_for_endpoint.client"),
    ("Engines.modules.systems.sentinel_one", "opentide.platforms.sentinel_one.client"),
    ("Engines.modules.systems.crowdstrike", "opentide.platforms.crowdstrike.client"),
    ("Engines.modules.systems.harfanglab", "opentide.platforms.harfanglab.client"),
    ("Engines.modules.systems.sentinel", "opentide.platforms.sentinel.client"),
    ("Engines.modules.systems.splunk", "opentide.platforms.splunk.client"),
    ("Engines.modules.systems.kql", "opentide.platforms.kql"),
    ("Engines.modules.datamodels.configurations", "opentide.loading.configurations"),
    ("Engines.modules.datamodels.objects", "opentide.loading.objects"),
    ("Engines.modules.deployment_planning", "opentide.deployment.planning"),
    ("Engines.modules.deployment_utils", "opentide.deployment.utils"),
    ("Engines.modules.documentation_components", "opentide.documentation.components"),
    ("Engines.modules.carbon_black_cloud", "opentide.platforms.carbon_black.client"),
    ("Engines.modules.config_models", "opentide.models.config_models"),
    ("Engines.modules.object_models", "opentide.models.object_models"),
    ("Engines.modules.system_models", "opentide.models.system_models"),
    ("Engines.deployment.carbon_black_cloud", "opentide.platforms.carbon_black.deployer"),
    ("Engines.deployment.defender_for_endpoint", "opentide.platforms.defender_for_endpoint.deployer"),
    ("Engines.deployment.sentinel_one", "opentide.platforms.sentinel_one.deployer"),
    ("Engines.deployment.crowdstrike", "opentide.platforms.crowdstrike.deployer"),
    ("Engines.deployment.harfanglab", "opentide.platforms.harfanglab.deployer"),
    ("Engines.deployment.sentinel", "opentide.platforms.sentinel.deployer"),
    ("Engines.deployment.splunk", "opentide.platforms.splunk.deployer"),
    ("Engines.validation.carbon_black_cloud_query", "opentide.platforms.carbon_black.validator"),
    ("Engines.validation.defender_for_endpoint_query", "opentide.platforms.defender_for_endpoint.validator"),
    ("Engines.validation.sentinel_one_query", "opentide.platforms.sentinel_one.validator"),
    ("Engines.validation.sentinel_query", "opentide.platforms.sentinel.validator"),
    ("Engines.validation.splunk_query", "opentide.platforms.splunk.validator"),
    ("Engines.validation.id_uniqueness", "opentide.validation.id_uniqueness"),
    ("Engines.validation.tide_schema", "opentide.validation.tide_schema"),
    ("Engines.validation.uuid_v4", "opentide.validation.uuid_v4"),
    ("Engines.framework.vscode_snippets", "opentide.generation.vscode_snippets"),
    ("Engines.framework.json_schemas", "opentide.generation.schema_pipeline"),
    ("Engines.framework.templates", "opentide.generation.template_renderer"),
    ("Engines.export.attack_navigator_layer", "opentide.export.attack_navigator_layer"),
    ("Engines.export.table_export", "opentide.export.table_export"),
    ("Engines.indexing.staging_indexer", "opentide.indexing.staging_indexer"),
    ("Engines.indexing.mdr_playbook_mapper", "opentide.export.playbook_map"),
    ("Engines.indexing.objects_indexer", "opentide.indexing.object_vocab"),
    ("Engines.indexing.revisions", "opentide.indexing.revisions"),
    ("Engines.indexing.indexer", "opentide.indexing.indexer"),
    ("Engines.mutation.promotion", "opentide.mutation.promotion"),
    ("Engines.mutation.security_domain", "opentide.mutation.security_domain"),
    ("Engines.mutation.references", "opentide.mutation.references"),
    ("Engines.mutation.file_name", "opentide.mutation.file_name"),
    ("Engines.templates.models", "opentide.documentation.templates.models"),
    ("Engines.templates.mdr", "opentide.documentation.templates.mdr"),
    ("Engines.templates.dom", "opentide.documentation.templates.dom"),
    ("Engines.documentation.wiki_navigation", "opentide.documentation.wiki_navigation"),
    ("Engines.documentation.vocabularies", "opentide.documentation.vocabularies"),
    ("Engines.documentation.metaschemas", "opentide.documentation.metaschemas"),
    ("Engines.documentation.models", "opentide.documentation.models"),
    ("Engines.documentation.dom", "opentide.documentation.dom"),
    ("Engines.documentation.mdr", "opentide.documentation.mdr"),
    ("Engines.modules._typing", "opentide.core.typing"),
    ("Engines.modules.environment", "opentide.core.environment"),
    ("Engines.modules.documentation", "opentide.documentation.core"),
    ("Engines.modules.deployment", "opentide.deployment"),
    ("Engines.modules.framework", "opentide.generation.framework"),
    ("Engines.modules.vocabulary", "opentide.generation.vocabulary"),
    ("Engines.modules.validation", "opentide.validation.legacy"),
    ("Engines.modules.git_repo", "opentide.deployment.git_repo"),
    ("Engines.modules.platforms", "opentide.platforms.plugins"),
    ("Engines.modules.plugins", "opentide.platforms.plugins"),
    ("Engines.modules.registry", "opentide.core.registry"),
    ("Engines.modules.splunk", "opentide.platforms.splunk.client"),
    ("Engines.modules.graphs", "opentide.documentation.graphs"),
    ("Engines.modules.index", "opentide.core.index_legacy"),
    ("Engines.modules.errors", "opentide.core.errors"),
    ("Engines.modules.debug", "opentide.core.debug"),
    ("Engines.modules.models", "opentide.models.legacy"),
    ("Engines.modules.enums", "opentide.models.deployment_enums"),
    ("Engines.modules.files", "opentide.core.files"),
    ("Engines.modules.logs", "opentide.core.logging"),
    ("Engines.modules.tide", "opentide.core.registry"),
    ("Engines.modules.ci", "opentide.deployment.ci"),
    ("Engines.validation.cve", "opentide.validation.cve"),
    ("Engines.mutation", "opentide.mutation"),
    ("Engines.export", "opentide.export"),
    ("Engines.extraction", "opentide.extraction"),
    ("Engines.documentation", "opentide.documentation"),
    ("Engines.framework", "opentide.generation"),
    ("Engines.indexing", "opentide.indexing"),
    ("Engines.deployment", "opentide.platforms"),
    ("Engines.validation", "opentide.validation"),
    ("Engines.templates", "opentide.documentation.templates"),
    ("Engines.modules", "opentide.core"),
]

PLATFORM_MODULE_MAP = {
    "carbon_black_cloud": "carbon_black",
    "defender_for_endpoint": "defender_for_endpoint",
    "sentinel_one": "sentinel_one",
    "crowdstrike": "crowdstrike",
    "harfanglab": "harfanglab",
    "sentinel": "sentinel",
    "splunk": "splunk",
}


def rewrite(text: str) -> str:
    for old, new in IMPORT_REWRITES:
        text = text.replace(old, new)
    for old_name, new_name in PLATFORM_MODULE_MAP.items():
        text = text.replace(f'f"Engines.deployment.{old_name}"', f'f"opentide.platforms.{new_name}.deployer"')
        text = text.replace(f'f"Engines.validation.{old_name}"', f'f"opentide.platforms.{new_name}.validator"')
        text = text.replace(f'"Engines.deployment.{old_name}"', f'"opentide.platforms.{new_name}.deployer"')
        text = text.replace(f'"Engines.validation.{old_name}_query"', f'"opentide.platforms.{new_name}.validator"')
    text = re.sub(r"^import git\n", "", text, flags=re.MULTILINE)
    text = re.sub(
        r"^sys\.path\.append\(str\(git\.Repo\([^)]*\)[^)]*\)\)\n",
        "",
        text,
        flags=re.MULTILINE,
    )
    return text


def main() -> None:
    changed = 0
    for path in OPENTIDE.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        new_text = rewrite(text)
        if new_text != text:
            path.write_text(new_text, encoding="utf-8")
            changed += 1
    print(f"Rewrote imports in {changed} files")


if __name__ == "__main__":
    main()
