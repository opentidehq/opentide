"""Runtime vocabulary enum resolution for validation and schema generation."""

from __future__ import annotations

import difflib
from typing import Any

from opentide.core.logging import get_logger
from opentide.generation.vocabulary import (
    VocabularyDefinition,
    entry_key_field,
    is_id_keyed,
)
from opentide.models.object_types import CORE_OBJECT_TYPES

logger = get_logger(__name__)

_STAGE_DESC_LIMIT = 300

_DROPDOWN = """
### {icon} {name}

{id_icon} **Identifier**: `{identifier}`

_Vocabulary_ : `{source_vocab}`

{criticality} {tlp}

{stage}

{link}

---

{description}
"""

_HINT_ABBREVS = (
    (" and ", " & "),
    (" without ", " w/o "),
    (" with ", " w/ "),
    (" to ", " "),
    (" of ", " "),
    (" a ", " "),
    (" an ", " "),
    ("Use", " "),
    ("used", " "),
    ("Using", " "),
)


class _VocabEnumBuilder:
    """Build enum value lists from vocabulary definitions (extracted from schema pipeline)."""

    def __init__(
        self,
        vocab: str,
        vocab_index: dict[str, VocabularyDefinition],
        *,
        extensions: dict[str, list[dict[str, Any]]],
        object_types: tuple[str, ...] | list[str],
        icons: dict[str, str],
        stages: str | list | None = None,
        no_wrap: bool = False,
        scoped: bool = False,
    ) -> None:
        self.vocab = vocab
        self.vocab_index = vocab_index
        self.extensions = extensions
        self.object_types = tuple(object_types)
        self.icons = icons
        self.scoped = scoped
        self.no_wrap = no_wrap
        self.filter_stages: list | None = [stages] if isinstance(stages, str) else stages
        self.enum: list[str] = []
        self.enum_description: list[str] = []
        self._hints: list[str] = []
        self._hint_descriptions: list[str] = []
        self._hints_enabled = False

    def resolve(self) -> tuple[list[str], list[str]]:
        logger.debug("resolving_vocab_enums", vocab=self.vocab)
        self._ingest(self.vocab_index.get(self.vocab))
        self._ingest_extensions()
        return self._finalise()

    def _ingest(self, vocab_data: VocabularyDefinition | None) -> None:
        if not vocab_data:
            logger.warning("vocabulary_not_found", vocab=self.vocab)
            return
        metadata = vocab_data.metadata
        self._hints_enabled = bool(metadata.get("vocab.search_hints", True))
        is_model = is_id_keyed(metadata.to_dict()) or (self.vocab in self.object_types)
        entries = {key: entry.as_dict() for key, entry in vocab_data.entries.items()}
        self._process(entries, is_model=is_model)

    def _ingest_extensions(self) -> None:
        extension_rows = self.extensions.get(self.vocab, [])
        if not extension_rows:
            return
        ext_vocab = self.vocab_index.get(self.vocab)
        ext_meta = ext_vocab.metadata if ext_vocab else None
        is_model = (is_id_keyed(ext_meta.to_dict()) if ext_meta else False) or (
            self.vocab in self.object_types
        )
        key_field = entry_key_field(key="id" if is_model else "name")
        normalised: dict[str, dict[str, Any]] = {}
        for ext in extension_rows:
            row = dict(ext)
            key = row.pop(key_field, None)
            if not key:
                logger.warning("extension_missing_key_field", key_field=key_field, vocab=self.vocab)
                continue
            normalised[str(key)] = row
        self._process(normalised, is_model=is_model)

    def _process(self, entries: dict[str, dict[str, Any]], *, is_model: bool) -> None:
        for key, data in entries.items():
            if is_model:
                value = key
                if self.scoped and data.get("tide.vocab.stages"):
                    raw_stages = data["tide.vocab.stages"]
                    stage = raw_stages[0] if isinstance(raw_stages, list) else raw_stages
                    value = f"{stage}::{key}"
                if self._emit(value, key, data) and self._hints_enabled:
                    self._hints.append(self._search_hint(value, data))
                    self._hint_descriptions.append(self.enum_description[-1])
            else:
                raw = data.get("tide.vocab.stages", [])
                stage_list = [raw] if not isinstance(raw, list) else raw
                matching = (
                    [stage for stage in stage_list if stage in self.filter_stages]
                    if self.filter_stages
                    else stage_list
                )
                if not self.scoped:
                    if not self.filter_stages or matching:
                        self._emit(key, key, data)
                elif matching:
                    for stage in matching:
                        self._emit(
                            f"{stage}::{key}",
                            key,
                            {**data, "tide.vocab.stages": stage},
                        )

    def _emit(self, value: str, entry_key: str, data: dict[str, Any]) -> bool:
        if value in self.enum:
            logger.info("skipping_duplicate_vocab_entry", vocab=self.vocab, value=value)
            return False
        self.enum.append(value)
        self.enum_description.append(self._dropdown(entry_key, data))
        return True

    def _finalise(self) -> tuple[list[str], list[str]]:
        if not self.enum:
            self.enum = [""]
        if self._hints and self._hints_enabled:
            self.enum.extend(self._hints)
            self.enum_description.extend(self._hint_descriptions)
        return self.enum, self.enum_description

    def _search_hint(self, value: str, data: dict[str, Any]) -> str:
        tips = data.get("name") or ""
        aliases = data.get("alias")
        if aliases:
            tips += ", " + ", ".join(aliases)
        hint = value + " #" + tips.strip()
        if not self.no_wrap and len(hint) > 60:
            for old, new in _HINT_ABBREVS:
                hint = hint.replace(old, new)
        return hint

    def _dropdown(self, name: str, key: dict[str, Any]) -> str:
        identifier = key.get("id") or name
        display = key.get("name") or name
        if display.islower():
            display = display.title()

        vocab_def = self.vocab_index.get(self.vocab)
        icon = (
            key.get("icon")
            or (vocab_def.metadata.icon if vocab_def else "")
            or self.icons.get(self.vocab, "")
        )
        source_vocab = vocab_def.metadata.name if vocab_def else None
        link = key.get("link") or ""
        stage = key.get("tide.vocab.stages") or ""
        tlp = key.get("tlp") or ""
        description = key.get("description") or ""

        criticality = ""
        if self.vocab in self.object_types:
            crit = key.get("criticality")
            crit_icon = self.icons.get("criticality", "")
            if crit:
                criticality = f"{crit_icon} **Criticality**: {crit}"

        id_icon = self.icons.get("id", "")
        stage_doc = ""
        if stage:
            stage_doc = f"_Stage_: `{stage}`"

        link_doc = f"[More information]({link})" if link else ""
        if isinstance(description, str) and len(description) > _STAGE_DESC_LIMIT:
            description = description[:_STAGE_DESC_LIMIT] + "…"

        return _DROPDOWN.format(
            icon=icon,
            name=display,
            id_icon=id_icon,
            identifier=identifier,
            source_vocab=source_vocab or self.vocab,
            criticality=criticality,
            tlp=f"**TLP**: {tlp}" if tlp else "",
            stage=stage_doc,
            link=link_doc,
            description=description,
        )


class RuntimeEnumResolver:
    """Resolve vocabulary enums at runtime with an explicit index (no module globals)."""

    def __init__(
        self,
        vocab_index: dict[str, VocabularyDefinition],
        *,
        extensions: dict[str, list[dict[str, Any]]] | None = None,
        object_types: tuple[str, ...] | list[str] | None = None,
        icons: dict[str, str] | None = None,
    ) -> None:
        self._vocab_index = vocab_index
        self._extensions = extensions or {}
        self._object_types = tuple(object_types or CORE_OBJECT_TYPES)
        self._icons = icons or {}

    def resolve(
        self,
        vocab: str,
        *,
        stages: str | list | None = None,
        scoped: bool = False,
        no_wrap: bool = False,
    ) -> tuple[list[str], list[str]]:
        cache_key = (vocab, scoped, no_wrap, _stages_key(stages))
        if not hasattr(self, "_cache"):
            self._cache: dict[tuple[Any, ...], tuple[list[str], list[str]]] = {}
        if cache_key in self._cache:
            return self._cache[cache_key]
        builder = _VocabEnumBuilder(
            vocab,
            self._vocab_index,
            extensions=self._extensions,
            object_types=self._object_types,
            icons=self._icons,
            stages=stages,
            no_wrap=no_wrap,
            scoped=scoped,
        )
        result = builder.resolve()
        self._cache[cache_key] = result
        return result

    def enum_values(
        self,
        vocab: str,
        *,
        stages: str | list | None = None,
        scoped: bool = False,
        no_wrap: bool = False,
    ) -> frozenset[str]:
        values, _ = self.resolve(vocab, stages=stages, scoped=scoped, no_wrap=no_wrap)
        return frozenset(v for v in values if v)

    def is_valid(
        self,
        value: str,
        vocab: str,
        *,
        stages: str | list | None = None,
        scoped: bool = False,
        no_wrap: bool = False,
    ) -> bool:
        from opentide.generation.framework import strip_vocab_stage_prefix

        allowed = self.enum_values(vocab, stages=stages, scoped=scoped, no_wrap=no_wrap)
        if value in allowed:
            return True
        stripped = strip_vocab_stage_prefix(vocab, value)
        return stripped in allowed or value in allowed

    def suggest(
        self,
        value: str,
        vocab: str,
        *,
        stages: str | list | None = None,
        scoped: bool = False,
        no_wrap: bool = False,
        cutoff: float = 0.5,
    ) -> str | None:
        allowed = list(self.enum_values(vocab, stages=stages, scoped=scoped, no_wrap=no_wrap))
        if not allowed:
            return None
        matches = difflib.get_close_matches(value, allowed, n=1, cutoff=cutoff)
        return matches[0] if matches else None


def _stages_key(stages: str | list | None) -> tuple[str, ...]:
    if stages is None:
        return ()
    if isinstance(stages, str):
        return (stages,)
    return tuple(stages)
