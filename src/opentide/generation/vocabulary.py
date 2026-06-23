"""Typed vocabulary models, loader, and TOML validation."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from opentide.core.logging import log

VocabKey = Literal["name", "id"]

VOCABULARY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["name", "field", "keys"],
    "properties": {
        "name": {"type": "string", "minLength": 1},
        "field": {"type": "string", "minLength": 1},
        "description": {"type": "string"},
        "icon": {"type": "string"},
        "key": {"type": "string", "enum": ["name", "id"]},
        "model": {"type": "boolean"},
        "keys": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name"],
            },
        },
        "stages": {
            "type": "array",
            "items": {
                "oneOf": [
                    {"type": "string"},
                    {
                        "type": "object",
                        "required": ["id"],
                        "properties": {
                            "id": {"type": "string"},
                            "name": {"type": "string"},
                            "description": {"type": "string"},
                            "icon": {"type": "string"},
                        },
                    },
                ]
            },
        },
    },
}

# Backward-compatible alias
VOCABULARY_YAML_SCHEMA = VOCABULARY_SCHEMA


class VocabularyLoadError(Exception):
    """Raised when a vocabulary definition cannot be loaded or validated."""


def normalize_stages(stages: str | list[str] | None) -> list[str]:
    """Normalise ``tide.vocab.stages`` to a list of stage identifiers."""
    if stages is None:
        return []
    if isinstance(stages, str):
        return [stages]
    return list(stages)


def resolve_vocab_key(raw: Mapping[str, Any], *, source: str = "") -> VocabKey:
    """Resolve entry keying from ``key`` or legacy ``model`` flag."""
    if "key" in raw:
        key = raw["key"]
        if key not in ("name", "id"):
            raise VocabularyLoadError(f"Invalid vocabulary key '{key}' in {source}")
        return key
    if raw.get("model"):
        if source:
            log("WARNING", "Deprecated 'model' flag; use key = \"id\"", source)
        return "id"
    return "name"


def entry_key_field(*, key: VocabKey | None = None, model: bool | None = None) -> str:
    """Return the canonical key field for vocabulary entries."""
    if key is not None:
        return key
    if model:
        return "id"
    return "name"


def is_id_keyed(metadata: Mapping[str, Any]) -> bool:
    """Return whether entries are indexed by external id."""
    if metadata.get("key") == "id":
        return True
    if metadata.get("key") == "name":
        return False
    return bool(metadata.get("model"))


_VOCAB_MODEL_CONFIG = ConfigDict(
    frozen=True, extra="allow", protected_namespaces=(), populate_by_name=True
)


class VocabularyMetadata(BaseModel):
    """Vocabulary document metadata (Pydantic document schema)."""

    model_config = _VOCAB_MODEL_CONFIG

    name: str
    field: str = ""
    description: str = ""
    icon: str = ""
    key: VocabKey = "name"
    model: bool = False
    stages: list[dict[str, Any]] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        known = {"name", "field", "description", "icon", "key", "model", "stages", "extra"}
        if key in known:
            value = getattr(self, key, None)
            if key == "stages":
                return list(value) if value else default
            if value not in (None, "", False, []):
                return value
        if key in self.extra:
            return self.extra[key]
        pydantic_extra = getattr(self, "__pydantic_extra__", None) or {}
        return pydantic_extra.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        payload = self.model_dump(exclude_none=True, exclude={"extra"})
        payload.update(self.extra)
        pydantic_extra = getattr(self, "__pydantic_extra__", None) or {}
        payload.update(pydantic_extra)
        if self.stages:
            payload["stages"] = [dict(stage) for stage in self.stages]
        return payload


class VocabularyEntry(BaseModel):
    """Single vocabulary entry."""

    model_config = _VOCAB_MODEL_CONFIG

    name: str
    description: str = ""
    icon: str = ""
    link: str = ""
    stages: tuple[str, ...] = Field(default_factory=tuple, alias="tide.vocab.stages")
    extra: dict[str, Any] = Field(default_factory=dict)

    @field_validator("stages", mode="before")
    @classmethod
    def _coerce_stages(cls, value: Any) -> tuple[str, ...]:
        if value is None:
            return ()
        if isinstance(value, str):
            return (value,)
        return tuple(value)

    def get(self, key: str, default: Any = None) -> Any:
        if key == "name":
            return self.name
        if key == "description":
            return self.description
        if key == "icon":
            return self.icon
        if key == "link":
            return self.link
        if key == "tide.vocab.stages":
            return self.stages
        if key in self.extra:
            return self.extra[key]
        pydantic_extra = getattr(self, "__pydantic_extra__", None) or {}
        return pydantic_extra.get(key, default)

    def __contains__(self, key: str) -> bool:
        return key in self.as_dict()

    def as_dict(self) -> dict[str, Any]:
        payload = self.model_dump(by_alias=True, exclude_none=True, exclude={"extra"})
        payload.update(self.extra)
        if self.stages:
            payload["tide.vocab.stages"] = list(self.stages)
        pydantic_extra = getattr(self, "__pydantic_extra__", None) or {}
        payload.update(pydantic_extra)
        return payload


class VocabularyDefinition(BaseModel):
    """Loaded vocabulary: metadata plus keyed entries."""

    model_config = _VOCAB_MODEL_CONFIG

    metadata: VocabularyMetadata
    entries: dict[str, VocabularyEntry]

    def to_index_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "entries": {key: entry.as_dict() for key, entry in self.entries.items()},
        }


def _validate_document_structure(raw: Mapping[str, Any], *, source: str) -> None:
    if not isinstance(raw, Mapping):
        raise VocabularyLoadError(f"Vocabulary document must be a mapping: {source}")
    for required in ("name", "field"):
        if required not in raw:
            raise VocabularyLoadError(
                f"Missing required key '{required}' in vocabulary document: {source}"
            )
    keys = raw.get("keys", [])
    if not isinstance(keys, list):
        raise VocabularyLoadError(f"Vocabulary 'keys' must be a list: {source}")


def parse_vocabulary_document(raw: Mapping[str, Any], *, source: str = "") -> VocabularyDefinition:
    """Parse a vocabulary document into a typed definition."""
    _validate_document_structure(raw, source=source)

    vocab_key = resolve_vocab_key(raw, source=source)
    metadata_raw = {key: value for key, value in raw.items() if key not in ("field", "keys")}
    key_field = entry_key_field(key=vocab_key)
    entries: dict[str, VocabularyEntry] = {}
    seen_keys: set[str] = set()

    for index, entry_data in enumerate(raw.get("keys", [])):
        if not isinstance(entry_data, Mapping):
            log("WARNING", f"Skipping malformed vocabulary entry at index {index}", source)
            continue
        if "name" not in entry_data:
            log("WARNING", f"Skipping entry missing 'name' at index {index}", source)
            continue
        if vocab_key == "id" and "id" not in entry_data:
            log("WARNING", f"Skipping id-keyed entry missing 'id' at index {index}", source)
            continue

        key_name = entry_data.get(key_field)
        if not key_name:
            log(
                "WARNING",
                f"Skipping vocabulary entry missing key field in {source}",
                f"index={index}",
            )
            continue
        key_str = str(key_name)
        if key_str in seen_keys:
            raise VocabularyLoadError(
                f"Duplicate entry key '{key_str}' in vocabulary {source} at index {index}"
            )
        seen_keys.add(key_str)

        try:
            entry = _build_entry(entry_data, fallback_name=str(entry_data["name"]))
        except VocabularyLoadError as exc:
            log("WARNING", str(exc), source, f"entry={key_str}")
            continue
        entries[key_str] = entry

    metadata = _build_metadata(metadata_raw, field=str(raw["field"]), vocab_key=vocab_key)
    return VocabularyDefinition(metadata=metadata, entries=entries)


def parse_yaml_vocabulary(raw: Mapping[str, Any], *, source: str = "") -> VocabularyDefinition:
    """Backward-compatible alias for :func:`parse_vocabulary_document`."""
    return parse_vocabulary_document(raw, source=source)


def _build_metadata(
    raw: Mapping[str, Any], *, field: str, vocab_key: VocabKey | None = None
) -> VocabularyMetadata:
    known = {"name", "description", "icon", "model", "key", "stages"}
    if vocab_key is None:
        vocab_key = resolve_vocab_key(raw)
    stages_raw = raw.get("stages") or []
    stages: list[dict[str, Any]] = []
    for stage in stages_raw:
        if isinstance(stage, Mapping):
            stages.append(dict(stage))
        elif isinstance(stage, str):
            stages.append({"name": stage})
    extra = {key: value for key, value in raw.items() if key not in known}
    is_id = vocab_key == "id"
    return VocabularyMetadata.model_validate(
        {
            "name": str(raw.get("name", "")),
            "field": field,
            "description": str(raw.get("description", "")),
            "icon": str(raw.get("icon", "")),
            "key": vocab_key,
            "model": is_id,
            "stages": stages,
            "extra": extra,
        }
    )


def _build_entry(entry_data: Mapping[str, Any], *, fallback_name: str) -> VocabularyEntry:
    reserved = {"name", "description", "icon", "link", "tide.vocab.stages"}
    stages = normalize_stages(entry_data.get("tide.vocab.stages"))
    extra = {key: value for key, value in entry_data.items() if key not in reserved}
    return VocabularyEntry.model_validate(
        {
            "name": str(entry_data.get("name", fallback_name)),
            "description": str(entry_data.get("description", "")),
            "icon": str(entry_data.get("icon", "")),
            "link": str(entry_data.get("link", "")),
            "tide.vocab.stages": stages,
            "extra": extra,
        }
    )


class VocabularyLoader:
    """Load and validate vocabulary definitions from index-shaped dicts."""

    @staticmethod
    def load(raw: Mapping[str, Any], *, source: str = "") -> VocabularyDefinition:
        if "metadata" not in raw:
            raise VocabularyLoadError(
                f"Missing 'metadata' in vocabulary definition{f' ({source})' if source else ''}"
            )
        if "entries" not in raw:
            raise VocabularyLoadError(
                f"Missing 'entries' in vocabulary definition{f' ({source})' if source else ''}"
            )

        metadata_raw = raw["metadata"]
        if not isinstance(metadata_raw, Mapping):
            raise VocabularyLoadError(f"Invalid metadata block in vocabulary {source}")

        field_name = str(metadata_raw.get("field", source))
        metadata = _build_metadata(metadata_raw, field=field_name)

        entries: dict[str, VocabularyEntry] = {}
        entries_raw = raw["entries"]
        if not isinstance(entries_raw, Mapping):
            raise VocabularyLoadError(f"Invalid entries block in vocabulary {source}")

        for key, entry_data in entries_raw.items():
            if not isinstance(entry_data, Mapping):
                log("WARNING", f"Skipping malformed vocabulary entry '{key}'", source)
                continue
            try:
                entries[str(key)] = _build_entry(entry_data, fallback_name=str(key))
            except VocabularyLoadError as exc:
                log("WARNING", str(exc), source, f"entry={key}")

        return VocabularyDefinition(metadata=metadata, entries=entries)

    @staticmethod
    def load_from_vocab_file(path: Path) -> VocabularyDefinition:
        from opentide.vocabulary.io import load_vocab_file

        return load_vocab_file(path)

    @staticmethod
    def load_from_yaml_file(path: Path) -> VocabularyDefinition:
        import yaml

        source = str(path)
        try:
            raw = yaml.safe_load(path.open(encoding="utf-8"))
        except Exception as exc:
            raise VocabularyLoadError(f"Could not read vocabulary YAML {source}: {exc}") from exc
        if not raw:
            raise VocabularyLoadError(f"Empty vocabulary YAML file: {source}")
        return parse_vocabulary_document(raw, source=source)

    @staticmethod
    def load_index(raw_vocabs: Mapping[str, Any] | None) -> dict[str, VocabularyDefinition]:
        """Load all vocabularies from an index vocabs mapping with per-file error boundaries."""
        if not raw_vocabs:
            log("FAILURE", "Vocabulary index is missing or empty")
            return {}

        loaded: dict[str, VocabularyDefinition] = {}
        for name, data in raw_vocabs.items():
            try:
                loaded[name] = VocabularyLoader.load(data, source=name)
            except VocabularyLoadError as exc:
                log("FAILURE", str(exc))
        return loaded
