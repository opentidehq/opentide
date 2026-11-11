"""Walk a platform block and document every setting it carries.

A rule page used to pick a handful of fields per platform (an alert title, an
entity mapping, the query), so most of a block never reached the docs and a
new field needed renderer code. :func:`flatten` walks the Pydantic model
instead: every value the block holds becomes a row, keyed by its YAML path
(``scheduling.frequency``) and described by the field's own docstring, the
text editors show on hover. Code (queries, YARA, investigation guides) is
lifted out into fenced blocks; a list of small objects becomes its own table.
A field the model gains is documented with no change here.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence, Set
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel
from pydantic.fields import FieldInfo

from opentide.documentation.facts.platforms import CodeLanguage
from opentide.documentation.markdown.text import first_sentence, inline_code, stringify

#: A setting path (indices removed) to the language of the code it holds.
CodeDetector = Callable[[str], CodeLanguage | None]

#: Longer plain text reads better as prose than as a code span.
_PROSE_LENGTH = 60
_DESCRIPTION_LENGTH = 160


@dataclass(frozen=True)
class Setting:
    """One scalar (or list of scalars) and where it sits in the block."""

    path: str
    value: str
    description: str = ""
    #: The model's default: the author did not write it, deploy still uses it.
    default: bool = False


@dataclass(frozen=True)
class CodeSetting:
    """A setting whose value is code, documented as a fenced block."""

    path: str
    code: str
    language: CodeLanguage | None
    description: str = ""


@dataclass(frozen=True)
class SettingTable:
    """A list of flat objects (exclusions, mappings, criteria), one row per item."""

    path: str
    columns: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]
    description: str = ""


@dataclass(frozen=True)
class Settings:
    """Everything a block sets, split by how a page shows it."""

    rows: list[Setting] = field(default_factory=list)
    code: list[CodeSetting] = field(default_factory=list)
    tables: list[SettingTable] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.rows or self.code or self.tables)


def flatten(
    model: BaseModel,
    *,
    exclude: Sequence[str] = (),
    code_language: CodeDetector = lambda _path: None,
) -> Settings:
    """Every value *model* holds, in declaration order.

    *exclude* names top-level keys documented elsewhere on the page.
    *code_language* names the language of a path that holds code; a value
    that spans lines, or a field marked multiline in the model, is code too.
    """
    settings = Settings()
    _Walker(settings, code_language).model(model, prefix="", exclude=set(exclude))
    return settings


@dataclass
class _Walker:
    out: Settings
    code_language: CodeDetector

    def model(self, model: BaseModel, *, prefix: str, exclude: Set[str] = frozenset()) -> None:
        fields = type(model).model_fields
        explicit = model.model_fields_set
        for name, info in fields.items():
            key = info.alias or name
            if not prefix and (key in exclude or name in exclude):
                continue
            value = getattr(model, name, None)
            self.value(
                value,
                path=f"{prefix}{key}",
                info=info,
                default=name not in explicit,
            )

    def value(self, value: Any, *, path: str, info: FieldInfo | None, default: bool) -> None:
        if _is_blank(value):
            return
        description = _description(info)
        if isinstance(value, BaseModel):
            self.model(value, prefix=f"{path}.")
            return
        if isinstance(value, Mapping):
            for key, item in value.items():
                self.value(item, path=f"{path}.{key}", info=None, default=default)
            return
        if isinstance(value, (list, tuple)):
            self.sequence(list(value), path=path, info=info, default=default)
            return
        if isinstance(value, str):
            language = self.code_language(_pattern(path))
            if language is not None or "\n" in value.strip() or _multiline(info):
                self.out.code.append(CodeSetting(path, value.rstrip("\n"), language, description))
                return
        self.out.rows.append(Setting(path, _scalar(value), description, default))

    def sequence(
        self, items: list[Any], *, path: str, info: FieldInfo | None, default: bool
    ) -> None:
        if all(_is_scalar(item) for item in items):
            text = ", ".join(_scalar(item, prose=False) for item in items if not _is_blank(item))
            self.out.rows.append(Setting(path, text, _description(info), default))
            return
        if all(isinstance(item, BaseModel) and _is_flat(item) for item in items) and not any(
            self._holds_code(item, path) for item in items
        ):
            self.out.tables.append(_table(items, path=path, description=_description(info)))
            return
        for index, item in enumerate(items):
            self.value(item, path=f"{path}[{index}]", info=info, default=default)

    def _holds_code(self, item: Any, path: str) -> bool:
        """Whether a field of *item* is code: a query belongs in a fenced block, not a cell."""
        if not isinstance(item, BaseModel):
            return False
        base = _pattern(path)
        for name, info in type(item).model_fields.items():
            value = getattr(item, name, None)
            if not isinstance(value, str) or not value.strip():
                continue
            if _multiline(info) or self.code_language(f"{base}.{info.alias or name}"):
                return True
        return False


def _table(items: list[BaseModel], *, path: str, description: str) -> SettingTable:
    columns: list[str] = []
    names: list[str] = []
    for item in items:
        for name, info in type(item).model_fields.items():
            key = info.alias or name
            if key not in columns and not _is_blank(getattr(item, name, None)):
                columns.append(key)
                names.append(name)
    rows = tuple(tuple(_cell(getattr(item, name, None)) for name in names) for item in items)
    return SettingTable(path, tuple(columns), rows, description)


def _cell(value: Any) -> str:
    if _is_blank(value):
        return "-"
    if isinstance(value, (list, tuple)):
        return ", ".join(_scalar(item, prose=False) for item in value)
    return _scalar(value)


def _scalar(value: Any, *, prose: bool = True) -> str:
    text = " ".join(stringify(value).split())
    if prose and isinstance(value, str) and len(text) > _PROSE_LENGTH and " " in text:
        return text
    return inline_code(text)


def _is_scalar(value: Any) -> bool:
    return not isinstance(value, (BaseModel, Mapping, list, tuple))


def _is_flat(model: BaseModel) -> bool:
    """Only scalars and lists of scalars: one table row can hold it."""
    for name in type(model).model_fields:
        value = getattr(model, name, None)
        if isinstance(value, (list, tuple)):
            if not all(_is_scalar(item) for item in value):
                return False
        elif not _is_scalar(value) or (isinstance(value, str) and "\n" in value.strip()):
            return False
    return True


def _is_blank(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, Mapping)):
        return not value
    return False


def _pattern(path: str) -> str:
    """``exclusions[0].query`` as ``exclusions.query``."""
    parts = []
    for part in path.split("."):
        parts.append(part.split("[", 1)[0])
    return ".".join(parts)


def _description(info: FieldInfo | None) -> str:
    if info is None or not info.description:
        return ""
    text = first_sentence(info.description, limit=_DESCRIPTION_LENGTH)
    # A sentence cut short can leave a code span open, which would swallow the row.
    return text.replace("`", "") if text.count("`") % 2 else text


def _multiline(info: FieldInfo | None) -> bool:
    extra = info.json_schema_extra if info is not None else None
    return isinstance(extra, dict) and bool(extra.get("tide.template.multiline"))
