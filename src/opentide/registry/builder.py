"""Build in-memory registry index from workspace and bundled data."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any

from opentide.core.files import resolve_configurations
from opentide.core.io import (
    describe_yaml_error,
    not_utf8_problem,
    parse_json,
    root_mapping_problem,
)
from opentide.core.logging import get_logger
from opentide.registry.catalogue import NESTED_INDEX_KEY, scan_object_dir
from opentide.registry.paths import legacy_path_aliases, resolve_workspace_paths
from opentide.registry.signals import index_objective_signals

logger = get_logger(__name__)

# Missing object dirs are normal before ``setup repo`` / first generate.
# Log each absent path once per process so generate-first ``setup vscode``
# does not spam error lines per phase × object type (issue #212).
_missing_object_folders_logged: set[str] = set()


#: Set while a caller reports unreadable object files itself (``validate`` turns
#: each into a ``yaml_parse`` diagnostic), so the file is not also logged. It
#: holds the files the registry could not read while it was set.
_caller_reports_parse_errors: ContextVar[list[dict[str, str]] | None] = ContextVar(
    "caller_reports_parse_errors", default=None
)


@contextmanager
def parse_errors_reported_by_caller() -> Generator[list[dict[str, str]]]:
    """Log object files the registry cannot load at DEBUG: the caller reports them.

    Yields the list of ``{"path", "error"}`` the registry could not read while
    the block ran, for a caller that reports them after the fact (``deploy``).
    """
    seen: list[dict[str, str]] = []
    token = _caller_reports_parse_errors.set(seen)
    try:
        yield seen
    finally:
        _caller_reports_parse_errors.reset(token)


def _log_parse_error(event: str, *, source: str, problem: str, **fields: str) -> None:
    """Log one object file the registry cannot load, or hand it to the caller that reports it."""
    seen = _caller_reports_parse_errors.get()
    if seen is None:
        logger.error(event, **fields)
        return
    logger.debug(event, **fields)
    seen.append({"path": source, "error": problem})


def _shown_path(path_str: str) -> str:
    """*path_str* relative to the current directory when inside it, for a log line."""
    path = Path(path_str)
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except (OSError, ValueError):
        return path_str


def reset_missing_object_folder_log_cache() -> None:
    """Test helper: allow the same absent path to be logged again."""
    _missing_object_folders_logged.clear()


def _log_missing_object_folder(
    object_dir: Path | None,
    *,
    error: bool,
    reason: str | None = None,
) -> None:
    """Log a missing object folder; debug when absent, error when unreadable."""
    path_key = str(object_dir) if object_dir is not None else ""
    if not error and path_key in _missing_object_folders_logged:
        return
    _missing_object_folders_logged.add(path_key)
    payload: dict[str, str] = {"path": path_key or "None"}
    if reason:
        payload["reason"] = reason
    if error:
        logger.error("could_not_find_object_folder", **payload)
    else:
        logger.debug("could_not_find_object_folder", **payload)


def _parse_yaml_file(path_str: str) -> tuple[str, dict[str, Any] | None, str | None, str]:
    """Worker: return (path, body, error, kind).

    ``kind`` is ``ok``, ``oserror`` for an unreadable file, or ``yaml`` for
    malformed content.
    """
    path = Path(path_str)
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        return path_str, None, str(exc), "oserror"
    except UnicodeDecodeError as exc:
        return path_str, None, not_utf8_problem(exc), "yaml"
    try:
        from opentide.core.io import parse_yaml

        body = parse_yaml(text)
    except Exception as exc:
        return path_str, None, describe_yaml_error(exc).message, "yaml"
    if (problem := root_mapping_problem(body)) is not None:
        return path_str, None, problem, "yaml"
    return path_str, body, None, "ok"


class RegistryBuilder:
    """Construct the monolithic index dict consumed by OpentideRegistry."""

    SKIPS = frozenset({"ram", "mdrv2"})

    def __init__(self) -> None:
        # Files the loader could not parse. Kept on the index so validation can
        # report them instead of silently dropping the object.
        self.parse_errors: list[dict[str, str]] = []
        # UUID -> the YAML file the object was read from. ``files`` keeps only
        # the basename, which is ambiguous once object folders are nested.
        self.file_paths: dict[str, str] = {}
        # YAML files in subfolders of an object folder: not object instances
        # (workspace 1.3, #584), so they are listed here instead of indexed.
        self.nested_object_files: list[dict[str, str]] = []
        # Files whose object a later file with the same UUID replaced: the index
        # keeps one object per UUID, so these are listed instead (``duplicate_id``).
        self.duplicate_files: list[dict[str, str]] = []

    def build(self) -> dict[str, Any]:
        configs = resolve_configurations()
        paths_cfg = configs["paths"]
        paths = resolve_workspace_paths(configs)
        metaschemas = paths_cfg.get("metaschemas", {})
        artifacts: dict[str, Any] = paths["_artifacts"]
        json_map: dict[str, str] = artifacts.get("schemas", {})
        template_map: dict[str, str] = artifacts.get("templates", {})

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
        index["subschemas"], index["templates"] = self._load_platform_templates(
            index["templates"], paths, configs
        )

        objects_index, files_index = self._load_objects(paths, metaschemas)
        index["parse_errors"] = self.parse_errors
        index["duplicate_files"] = self.duplicate_files
        index[NESTED_INDEX_KEY] = self.nested_object_files
        from opentide.indexing.inflight import apply_inflight_overlay, inflight_preview_enabled

        # Shards are other pull requests' unreviewed objects. Deploy and
        # validate resolve rules from this index, so only preview output
        # (``inflight_preview``) may read them.
        if inflight_preview_enabled():
            apply_inflight_overlay(objects_index, inflight_dir=paths.get("inflight"))
        index["objects"] = objects_index
        index["files"] = files_index
        index["file_paths"] = self.file_paths

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
            if identifier in json_index:
                continue
            try:
                json_index[identifier] = parse_json(schema_path.read_bytes())
            except (OSError, ValueError) as exc:
                # A truncated or hand-broken artifact: every command would fail
                # on it until regenerated. Skip it, and say which file it is. A
                # warning: nothing but the MCP schema resource reads it, and an
                # error would fail `generate`, the command that rewrites it.
                logger.warning(
                    "could_not_read_schema_artifact",
                    path=_shown_path(str(schema_path)),
                    error=str(exc),
                    advice="Run `opentide generate schemas` or `opentide generate` to rewrite it.",
                )

        return framework_paths, json_index

    def _load_json_schemas(self, schema_dir: Path, json_map: dict[str, str]) -> dict[str, Any]:
        """Legacy helper — prefer :meth:`_scan_framework_schemas`."""
        _, json_index = self._scan_framework_schemas(schema_dir, json_map)
        return json_index

    def _load_metaschemas(self, metaschemas: dict[str, str]) -> dict[str, Any]:
        from opentide._models.schema_registry import models_for_family
        from opentide.generation.pydantic_metaschema import build_schema_source_for_identifier

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

    def _load_platform_templates(
        self,
        template_index: dict[str, Any],
        paths: dict[str, Path],
        configs: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Index each configured platform's block schema source and bundled template.

        Both are filed under ``"systems"``, the key the platform block
        resolvers read.
        """
        from opentide._models.platform import PLATFORM_CONFIG_MODELS
        from opentide._models.platform_schema import platform_model_for_key
        from opentide.generation.pydantic_metaschema import build_platform_schema_source
        from opentide.package.paths import platform_template_name

        schemas: dict[str, Any] = {}
        templates: dict[str, Any] = template_index.setdefault("systems", {})
        bundled = paths["platform_templates"]
        platforms = configs.get("platforms", {})
        for platform, document in platforms.items():
            if not isinstance(document, dict) or not isinstance(document.get("platform"), dict):
                continue
            # No rule block exists for a platform without a model (a plugin's
            # `platforms/<id>.toml`): nothing to index (#736).
            if platform not in PLATFORM_CONFIG_MODELS:
                continue
            schemas[platform] = build_platform_schema_source(platform_model_for_key(platform))
            template_file = bundled / platform_template_name(platform)
            if template_file.is_file():
                templates[platform] = template_file.read_text(encoding="utf-8")
        return {"systems": schemas}, template_index

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
            if object_dir is None:
                _log_missing_object_folder(None, error=False)
                continue
            try:
                exists = object_dir.exists()
            except OSError as exc:
                _log_missing_object_folder(object_dir, error=True, reason=str(exc))
                continue
            if not exists:
                _log_missing_object_folder(object_dir, error=False)
                continue
            if not object_dir.is_dir():
                _log_missing_object_folder(object_dir, error=True, reason="not_a_directory")
                continue
            try:
                scan = scan_object_dir(object_dir)
            except OSError as exc:
                _log_missing_object_folder(object_dir, error=True, reason=str(exc))
                continue
            for model_path in scan.files:
                yaml_files.append((meta_name, str(model_path)))
            self.nested_object_files.extend(
                {"path": str(path), "folder": str(object_dir), "object_type": meta_name}
                for path in scan.nested
            )

        if self.nested_object_files:
            logger.info(
                "nested_object_files_skipped",
                count=len(self.nested_object_files),
                files=[row["path"] for row in self.nested_object_files],
            )

        if not yaml_files:
            return objects_index, files_index

        self._load_object_files(yaml_files, objects_index, files_index)

        return objects_index, files_index

    def _ingest_object(
        self,
        meta_name: str,
        model_path: Path,
        body: dict[str, Any],
        objects_index: dict[str, Any],
        files_index: dict[str, str],
    ) -> None:
        metadata = body.get("metadata")
        meta_uuid = metadata.get("uuid") if isinstance(metadata, dict) else None
        identifier = body.get("uuid") or meta_uuid
        if not identifier:
            _log_parse_error(
                "missing_identifier_from_model",
                source=str(model_path),
                problem="object YAML has no uuid",
                file=str(model_path),
            )
            self.parse_errors.append(
                {
                    "path": str(model_path),
                    "object_type": meta_name,
                    "error": "object YAML has no uuid",
                    "code": "missing_uuid",
                    "message": f"Object YAML has no uuid: {model_path.name}",
                }
            )
            return
        model_cat = objects_index[meta_name]
        displaced = self.file_paths.get(identifier) if identifier in model_cat else None
        if displaced is not None and displaced != str(model_path):
            message = f"UUID {identifier} is also used by {_shown_path(str(model_path))}"
            self.duplicate_files.append(
                {
                    "path": displaced,
                    "object_type": meta_name,
                    "code": "duplicate_id",
                    "error": message,
                    "message": message,
                }
            )
        model_cat[identifier] = body
        files_index[identifier] = model_path.name
        self.file_paths[identifier] = str(model_path)
        if meta_name == "objective":
            index_objective_signals(
                objects_index["signal"], identifier, body, source=model_path.name
            )

    def _load_object_files(
        self,
        yaml_files: list[tuple[str, str]],
        objects_index: dict[str, Any],
        files_index: dict[str, str],
    ) -> None:
        """Parse and ingest object YAML files.

        Deliberately sequential. The registry is built during module import, so a
        process pool here breaks the `opentide` console script: `spawn` children
        re-import the unguarded entry point, rebuild the registry, and try to spawn
        again, which Python refuses. Parsing is also CPU-bound under the C YAML
        loader, so pool overhead measured slower than sequential at every corpus
        size up to 5k objects.
        """
        for meta_name, path_str in yaml_files:
            _, body, error, kind = _parse_yaml_file(path_str)
            if error or body is None:
                event = "unreadable_object_file" if kind == "oserror" else "malformed_object_yaml"
                _log_parse_error(
                    event,
                    source=path_str,
                    problem=error or root_mapping_problem(body) or "",
                    path=_shown_path(path_str),
                    error=error or "",
                )
                self.parse_errors.append(
                    {
                        "path": path_str,
                        "object_type": meta_name,
                        "error": error or root_mapping_problem(body) or "",
                    }
                )
                continue
            self._ingest_object(meta_name, Path(path_str), body, objects_index, files_index)


def build_registry() -> dict[str, Any]:
    """Build and return the in-memory registry index."""
    return RegistryBuilder().build()
