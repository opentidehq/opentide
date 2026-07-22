"""Build in-memory registry index from workspace and bundled data."""

from __future__ import annotations

import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from opentide.core.files import resolve_configurations
from opentide.core.io import load_yaml, parse_json
from opentide.core.logging import get_logger
from opentide.registry.paths import legacy_path_aliases, resolve_workspace_paths

logger = get_logger(__name__)


def _parse_yaml_file(path_str: str) -> tuple[str, dict[str, Any] | None, str | None]:
    """Worker: return (path, body, error)."""
    path = Path(path_str)
    try:
        body = load_yaml(path)
        if not isinstance(body, dict):
            return path_str, None, "YAML root must be a mapping"
        return path_str, body, None
    except Exception as exc:
        return path_str, None, str(exc)


class RegistryBuilder:
    """Construct the monolithic index dict consumed by OpenTideRegistry."""

    SKIPS = frozenset({"ram", "mdrv2"})

    def build(self) -> dict[str, Any]:
        configs = resolve_configurations()
        paths_cfg = configs.get("paths") or configs["global"]
        paths = resolve_workspace_paths(configs)
        metaschemas = paths_cfg.get("metaschemas", {})
        artifacts: dict[str, Any] = paths["_artifacts"]
        json_map: dict[str, str] = artifacts.get("schemas", {})
        template_map: dict[str, str] = artifacts.get("templates", {})
        recomposition = paths_cfg.get("recomposition", {})

        index: dict[str, Any] = {
            "paths": legacy_path_aliases(paths),
            "configurations": configs,
        }

        index["vocabs"] = self._load_vocabularies(paths["vocabularies"])
        framework_paths, json_schemas = self._scan_framework_schemas(
            paths["json_schemas"], json_map
        )
        index["framework_schemas"] = framework_paths
        index["json_schemas"] = json_schemas
        index["metaschemas"] = self._load_metaschemas(metaschemas)
        index["definitions"] = self._load_definitions()
        index["templates"] = self._load_templates(paths["templates"], template_map)
        index["subschemas"], index["templates"] = self._load_recomposition(
            index["templates"], paths, configs, recomposition
        )

        objects_index, files_index = self._load_objects(paths, metaschemas)
        from opentide.indexing.inflight import apply_inflight_overlay

        apply_inflight_overlay(objects_index, inflight_dir=paths.get("inflight"))
        index["objects"] = objects_index
        index["files"] = files_index

        from opentide.indexing.object_vocab import build_object_vocabularies

        doc_config = configs.get("documentation", {})
        object_vocab = build_object_vocabularies(
            object_scope=paths_cfg.get("objects", []),
            models_index=objects_index,
            icons=doc_config.get("icons", {}),
            object_names=doc_config.get("object_names", {}),
        )
        index["vocabs"].update(object_vocab)
        index["indexes"] = {"objects": object_vocab}

        return index

    def _load_vocabularies(self, vocab_root: Path) -> dict[str, Any]:
        from opentide.vocabulary.io import load_vocab_file

        voc_index: dict[str, Any] = {}
        if not vocab_root.is_dir():
            return voc_index
        for voc_file in sorted(vocab_root.glob("*.vocab.toml")):
            try:
                vocabulary = load_vocab_file(voc_file)
            except Exception as exc:
                logger.error("could_not_read_vocabulary", name=voc_file.name, error=str(exc))
                continue
            voc_index[vocabulary.metadata.field] = vocabulary.to_index_dict()
        return voc_index

    def _scan_framework_schemas(
        self,
        schema_dir: Path,
        json_map: dict[str, str],
    ) -> tuple[dict[str, Path], dict[str, Any]]:
        """Scan ``.opentide/schemas/*.schema.json`` and build in-memory indexes."""
        from opentide.registry.artifacts import parse_schema_artifact_name

        framework_paths: dict[str, Path] = {}
        json_index: dict[str, Any] = {}
        if not schema_dir.is_dir():
            return framework_paths, json_index

        for path in sorted(schema_dir.glob("*.schema.json")):
            if path.name == "opentide.schema.json":
                continue
            try:
                identifier = parse_schema_artifact_name(path.name)
                content = parse_json(path.read_bytes())
            except Exception:
                continue
            framework_paths[identifier] = path
            json_index[identifier] = content

        for meta_name, filename in json_map.items():
            if meta_name in ("router", "visibility"):
                continue
            schema_path = schema_dir / filename
            if not schema_path.is_file():
                continue
            try:
                identifier = parse_schema_artifact_name(filename)
            except ValueError:
                identifier = meta_name
            if identifier not in json_index:
                json_index[identifier] = parse_json(schema_path.read_bytes())

        return framework_paths, json_index

    def _load_json_schemas(self, schema_dir: Path, json_map: dict[str, str]) -> dict[str, Any]:
        """Legacy helper — prefer :meth:`_scan_framework_schemas`."""
        _, json_index = self._scan_framework_schemas(schema_dir, json_map)
        return json_index

    def _load_metaschemas(self, metaschemas: dict[str, str]) -> dict[str, Any]:
        from opentide.generation.pydantic_metaschema import build_schema_source_for_identifier
        from opentide.models.schema_registry import models_for_family

        result: dict[str, Any] = {}
        for family in metaschemas:
            for schema_id in models_for_family(family):
                result[schema_id] = build_schema_source_for_identifier(schema_id)
        return result

    def _load_definitions(self) -> dict[str, Any]:
        from opentide.generation.pydantic_metaschema import build_definition_index

        return build_definition_index()

    def _load_templates(self, template_dir: Path, template_map: dict[str, str]) -> dict[str, Any]:
        template_index: dict[str, Any] = {}
        if not template_dir.is_dir():
            return template_index
        for cat, filename in template_map.items():
            template_path = template_dir / filename
            if template_path.is_file():
                template_index[cat] = template_path.read_text(encoding="utf-8")
        return template_index

    def _load_recomposition(
        self,
        template_index: dict[str, Any],
        paths: dict[str, Path],
        configs: dict[str, Any],
        recomposition: dict[str, str],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        from opentide.generation.pydantic_metaschema import build_platform_schema_source
        from opentide.models.platform_schema import platform_model_for_key

        subschemas_index: dict[str, Any] = {}
        sub_path = paths["platform_templates"]
        for recomp, folder in recomposition.items():
            template_index.setdefault(recomp, {})
            subschemas_index[recomp] = {}
            recomp_data = configs.get(recomp, configs.get("systems", {}))
            sub_templates_path = sub_path / folder / "Templates"
            for data, entry in recomp_data.items():
                if not isinstance(entry, dict):
                    continue
                platform_section = entry.get("platform") or entry.get("tide") or {}
                sub_name = (
                    platform_section.get("name") or platform_section.get("subschema") or str(data)
                )
                if not platform_section:
                    continue
                platform_model = platform_model_for_key(data)
                subschemas_index[recomp][data] = build_platform_schema_source(platform_model)
                template_file = sub_templates_path / f"{sub_name} Template.yaml"
                if template_file.is_file():
                    template_index[recomp][data] = template_file.read_text(encoding="utf-8")
        return subschemas_index, template_index

    def _load_objects(
        self,
        paths: dict[str, Path],
        metaschemas: dict[str, str],
    ) -> tuple[dict[str, Any], dict[str, str]]:
        objects_index: dict[str, Any] = {name: {} for name in metaschemas}
        objects_index["signal"] = {}
        files_index: dict[str, str] = {}

        yaml_files: list[tuple[str, str]] = []
        for meta_name in metaschemas:
            if meta_name in self.SKIPS:
                continue
            object_dir = paths.get(meta_name)
            if object_dir is None or not object_dir.is_dir():
                logger.error("could_not_find_object_folder", path=str(object_dir))
                continue
            for model_path in sorted(object_dir.rglob("*.yaml")):
                if model_path.name.endswith(".debug.yaml"):
                    continue
                yaml_files.append((meta_name, str(model_path)))

        if not yaml_files:
            return objects_index, files_index

        workers = min(8, max(1, os.cpu_count() or 1))
        if os.environ.get("OPENTIDE_REGISTRY_WORKERS", "").strip() == "0":
            workers = 1
        if workers > 1 and len(yaml_files) > 4:
            self._load_objects_parallel(yaml_files, objects_index, files_index)
        else:
            self._load_objects_sequential(yaml_files, objects_index, files_index)

        return objects_index, files_index

    def _ingest_object(
        self,
        meta_name: str,
        model_path: Path,
        body: dict[str, Any],
        objects_index: dict[str, Any],
        files_index: dict[str, str],
    ) -> None:
        identifier = body.get("uuid") or body.get("metadata", {}).get("uuid")
        if not identifier:
            logger.error("missing_identifier_from_model", file=model_path.name)
            return
        model_cat = objects_index[meta_name]
        model_cat[identifier] = body
        files_index[identifier] = model_path.name
        if meta_name == "objective":
            objective = body.get("objective")
            if not isinstance(objective, dict):
                return
            signals = objective.get("signals") or []
            if not isinstance(signals, list):
                return
            for signal in signals:
                if not isinstance(signal, dict):
                    continue
                signal_uuid = signal.get("uuid")
                if not signal_uuid:
                    logger.error(
                        "signal_missing_uuid_in_objective",
                        objective=model_path.name,
                    )
                    continue
                signal_copy = signal.copy()
                signal_copy["parent"] = identifier
                objects_index["signal"][str(signal_uuid)] = signal_copy

    def _load_objects_sequential(
        self,
        yaml_files: list[tuple[str, str]],
        objects_index: dict[str, Any],
        files_index: dict[str, str],
    ) -> None:
        for meta_name, path_str in yaml_files:
            _, body, error = _parse_yaml_file(path_str)
            if error or body is None:
                logger.error("failed_to_parse_yaml", path=path_str, error=error or "")
                continue
            self._ingest_object(meta_name, Path(path_str), body, objects_index, files_index)

    def _load_objects_parallel(
        self,
        yaml_files: list[tuple[str, str]],
        objects_index: dict[str, Any],
        files_index: dict[str, str],
    ) -> None:
        path_only = [p for _, p in yaml_files]
        meta_by_path = {p: m for m, p in yaml_files}
        with ProcessPoolExecutor(max_workers=min(8, len(path_only))) as pool:
            futures = {pool.submit(_parse_yaml_file, p): p for p in path_only}
            for future in as_completed(futures):
                path_str = futures[future]
                _, body, error = future.result()
                if error or body is None:
                    logger.error("failed_to_parse_yaml", path=path_str, error=error or "")
                    continue
                meta_name = meta_by_path[path_str]
                self._ingest_object(meta_name, Path(path_str), body, objects_index, files_index)


def build_registry() -> dict[str, Any]:
    """Build and return the in-memory registry index."""
    return RegistryBuilder().build()
