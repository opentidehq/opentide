"""In-memory graph preflight for object refs, chaining, and vocabulary enums."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from opentide.core.index_manager import IndexManager
from opentide.generation.vocabulary import VocabularyDefinition, VocabularyLoader
from opentide.indexing.object_vocab import build_object_vocabularies
from opentide.models.object_types import CORE_OBJECT_TYPES
from opentide.validation.vocab_resolver import RuntimeEnumResolver


@dataclass(frozen=True)
class ObjectRef:
    uuid: str
    name: str
    object_type: str
    file_path: Path | None = None


class PreflightGraph:
    """Single-pass registry graph for validation and LSP interrogation."""

    def __init__(
        self,
        *,
        objects_by_type: dict[str, dict[str, dict[str, Any]]],
        objects_by_uuid: dict[str, ObjectRef],
        files_index: dict[str, str],
        chaining_graph: dict[str, Any],
        enum_resolver: RuntimeEnumResolver,
    ) -> None:
        self._objects_by_type = objects_by_type
        self._objects_by_uuid = objects_by_uuid
        self._files_index = files_index
        self._chaining_graph = chaining_graph
        self._enum_resolver = enum_resolver

    @classmethod
    def build(cls, index: dict[str, Any]) -> PreflightGraph:
        configurations = index.get("configurations", {})
        global_config = configurations.get("global", {})
        doc_config = configurations.get("documentation", {})
        objects = dict(index.get("objects", {}))

        vocabs_raw = dict(index.get("vocabs", {}))
        object_vocabs = build_object_vocabularies(
            object_scope=global_config.get("objects", list(CORE_OBJECT_TYPES)),
            models_index=objects,
            icons=doc_config.get("icons", {}),
            object_names=doc_config.get("object_names", {}),
        )
        vocabs_raw.update(object_vocabs)

        vocab_index = VocabularyLoader.load_index(vocabs_raw)
        schema_config = configurations.get("schema", {})
        extensions = schema_config.get("vocabulary", {})
        icons = doc_config.get("icons", {})

        enum_resolver = RuntimeEnumResolver(
            vocab_index,
            extensions=extensions,
            object_types=global_config.get("objects", list(CORE_OBJECT_TYPES)),
            icons=icons,
        )

        files_index = dict(index.get("files", {}))
        paths = index.get("paths", {})
        tide_paths = paths.get("tide", paths)

        objects_by_uuid: dict[str, ObjectRef] = {}
        for object_type, registry in objects.items():
            if object_type not in CORE_OBJECT_TYPES and object_type != "signal":
                continue
            for uuid, body in registry.items():
                file_name = files_index.get(uuid)
                file_path: Path | None = None
                if file_name and object_type in tide_paths:
                    file_path = Path(tide_paths[object_type]) / file_name
                objects_by_uuid[uuid] = ObjectRef(
                    uuid=uuid,
                    name=str(body.get("name", uuid)),
                    object_type=object_type,
                    file_path=file_path,
                )

        threats = objects.get("threat", {})
        chaining_graph = IndexManager.compute_chains(threats) if threats else {}

        return cls(
            objects_by_type=objects,
            objects_by_uuid=objects_by_uuid,
            files_index=files_index,
            chaining_graph=chaining_graph,
            enum_resolver=enum_resolver,
        )

    @property
    def enum_resolver(self) -> RuntimeEnumResolver:
        return self._enum_resolver

    def enum_values(
        self,
        ref: str,
        *,
        stages: str | list | None = None,
        scoped: bool = False,
        no_wrap: bool = False,
    ) -> frozenset[str]:
        if ref in CORE_OBJECT_TYPES or ref in ("threat", "objective", "rule", "signal"):
            registry = self._objects_by_type.get(ref, {})
            return frozenset(registry.keys())
        return self._enum_resolver.enum_values(ref, stages=stages, scoped=scoped, no_wrap=no_wrap)

    def resolve(self, uuid: str) -> ObjectRef | None:
        return self._objects_by_uuid.get(uuid)

    def parent_uuids(self, uuid: str) -> list[str]:
        from opentide.generation.framework import parents

        return parents(uuid)

    def chaining_neighbors(self, tvm_uuid: str) -> dict[str, list[str]]:
        return dict(self._chaining_graph.get(tvm_uuid, {}))

    def suggest_ref(self, ref_type: str, bad_value: str) -> str | None:
        if ref_type in CORE_OBJECT_TYPES:
            allowed = [self._objects_by_uuid[u].name for u in self.enum_values(ref_type)]
            import difflib

            matches = difflib.get_close_matches(bad_value, allowed, n=1, cutoff=0.5)
            if matches:
                name = matches[0]
                for ref in self._objects_by_uuid.values():
                    if ref.name == name and ref.object_type == ref_type:
                        return ref.uuid
            return None
        return self._enum_resolver.suggest(bad_value, ref_type)

    def format_invalid_ref(self, ref_type: str, value: str) -> str:
        suggestion = self.suggest_ref(ref_type, value)
        if suggestion:
            ref = self.resolve(suggestion)
            label = ref.name if ref else suggestion
            return (
                f"Unknown {ref_type} reference {value!r} — did you mean {label!r} ({suggestion})?"
            )
        return f"Unknown {ref_type} reference {value!r}"

    def vocab_definitions(self) -> dict[str, VocabularyDefinition]:
        return dict(self._enum_resolver._vocab_index)
