"""System information services."""

from __future__ import annotations

import types
from typing import TYPE_CHECKING, Any, Union, get_args, get_origin

from opentide.cli.enums import DetectionPlatform, platform_label
from opentide.core.index_manager import IndexManager
from opentide.core.logging.config import get_stdout_console
from opentide.core.object_fields import as_body, matches_technique, object_platforms
from opentide.core.registry import Opentide
from opentide.generation.vocabulary import (
    VocabularyDefinition,
    VocabularyRevisionResolver,
    parse_semver,
    parse_vocab_contract,
)
from opentide.platforms.enabled import enabled_systems

if TYPE_CHECKING:
    from rich.table import Table

    from opentide.cli.context import CliContext

#: Human titles for the object sections, keyed by section and ``Opentide.Models`` family.
_SECTION_TITLES = {"rules": "Rules", "threats": "Threats", "objectives": "Objectives"}


class UnknownVocabularyError(LookupError):
    """``info vocab <name>`` named a vocabulary the engine does not load."""

    def __init__(self, name: str, available: list[str]) -> None:
        self.name = name
        self.available = available
        super().__init__(f"Unknown vocabulary: {name}. Available: {', '.join(available)}")


def collect_info(
    ctx: CliContext,
    *,
    platform: DetectionPlatform | None = None,
    section: str | None = None,
    technique: str | None = None,
    vocab: str | None = None,
) -> dict[str, Any]:
    """Collect system information about the detection repository.

    Raises :class:`UnknownVocabularyError` when the ``vocab`` section names a
    vocabulary that is not loaded.
    """
    ctx.apply_environment()
    Opentide.reload()
    parse_errors = list(IndexManager.load().get("parse_errors") or [])
    enabled_platforms = set(enabled_systems())
    platforms_info = []
    for name, plat in Opentide.Platforms.items():
        if platform is not None and name != platform.value:
            continue
        platforms_info.append(
            {
                "name": name,
                "enabled": name in enabled_platforms,
                "can_deploy": plat.can_deploy,
                "can_validate": plat.can_validate,
            }
        )
    payload: dict[str, Any] = {
        "version": _package_version(),
        "repo": str(ctx.repo),
        "counts": {
            "rules": len(Opentide.Models.rules),
            "threats": len(Opentide.Models.threats),
            "objectives": len(Opentide.Models.objectives),
        },
        "parse_error_count": len(parse_errors),
        "platforms": platforms_info,
    }
    if section == "rules":
        payload["rules"] = list(Opentide.Models.rules.keys())
    elif section == "threats":
        payload["threats"] = list(Opentide.Models.threats.keys())
    elif section == "objectives":
        payload["objectives"] = list(Opentide.Models.objectives.keys())
    elif section == "coverage" and technique:
        payload["coverage"] = _technique_coverage(technique)
    elif section == "vocab":
        vocabularies = _file_vocabularies()
        if vocab is None:
            payload["vocabularies"] = [
                _vocab_overview(name, definition) for name, definition in vocabularies.items()
            ]
        elif vocab not in vocabularies:
            raise UnknownVocabularyError(vocab, list(vocabularies))
        else:
            payload["vocabulary"] = _vocab_detail(vocab, vocabularies[vocab])
    return payload


def render_info(payload: dict[str, Any], *, section: str | None = None) -> None:
    """Print the human view of :func:`collect_info`: the section asked for, else the summary."""
    console = get_stdout_console()
    if section == "coverage":
        coverage = payload["coverage"]
        count = coverage["count"]
        console.print(
            f"Coverage for {coverage['technique']}: {count} rule{'' if count == 1 else 's'}",
            markup=False,
        )
        if coverage["rules"]:
            console.print(_objects_table("rules", coverage["rules"]))
    elif section == "vocab":
        if "vocabulary" in payload:
            for table in _vocab_detail_tables(payload["vocabulary"]):
                console.print(table)
        else:
            console.print(_vocab_list_table(payload["vocabularies"]))
    elif section in _SECTION_TITLES:
        uuids = payload[section]
        if uuids:
            console.print(_objects_table(section, uuids))
        else:
            console.print(f"No {section} found")
    else:
        console.print(_summary_table(payload))


def _summary_table(payload: dict[str, Any]) -> Table:
    from rich.table import Table
    from rich.text import Text

    table = Table(title="opentide Info")
    table.add_column("Key")
    table.add_column("Value")
    table.add_row("Version", Text(str(payload["version"])))
    for family, title in _SECTION_TITLES.items():
        table.add_row(title, str(payload["counts"][family]))
    table.add_row("Parse errors", str(payload.get("parse_error_count", 0)))
    for plat in payload["platforms"]:
        caps = []
        if plat["can_deploy"]:
            caps.append("deploy")
        if plat["can_validate"]:
            caps.append("validate")
        try:
            display_name = platform_label(DetectionPlatform(plat["name"]))
        except ValueError:
            display_name = plat["name"]
        table.add_row(
            Text(display_name),
            Text(f"enabled={plat['enabled']} [{', '.join(caps) or 'none'}]"),
        )
    return table


def _objects_table(family: str, uuids: list[str]) -> Table:
    """UUID and name per object; rules also list the platforms they configure."""
    from rich.table import Table
    from rich.text import Text

    objects = getattr(Opentide.Models, family)
    table = Table(title=f"{_SECTION_TITLES[family]} ({len(uuids)})")
    table.add_column("UUID", no_wrap=True, min_width=36)
    table.add_column("Name", overflow="fold")
    if family == "rules":
        table.add_column("Platforms", overflow="fold")
    for uuid in uuids:
        body = as_body(objects.get(uuid))
        row = [Text(uuid), Text(str(body.get("name") or ""))]
        if family == "rules":
            row.append(Text(", ".join(sorted(object_platforms(body)))))
        table.add_row(*row)
    return table


def _package_version() -> str:
    from opentide import __version__

    return __version__


def _technique_coverage(technique: str) -> dict[str, Any]:
    """Return rules referencing an ATT&CK technique."""
    needle = technique.strip()
    matching = [
        uuid for uuid, rule in Opentide.Models.rules.items() if matches_technique(rule, needle)
    ]
    return {"technique": needle, "rules": matching, "count": len(matching)}


def _file_vocabularies() -> dict[str, VocabularyDefinition]:
    """Vocabularies the engine loaded from ``*.vocab.toml`` files, sorted by name.

    Read through the registry, so the set is the one validation and schema
    generation use. The object vocabularies (``rules``, ``threats``, …) that
    the index builds from the repository's own objects carry no key lifecycle
    and are left out.
    """
    index: dict[str, VocabularyDefinition] = Opentide.Vocabularies.Index
    object_vocabs = set(Opentide.Configuration.Global.objects)
    return {name: index[name] for name in sorted(index) if name not in object_vocabs}


def _revision(raw: str) -> str:
    """Normalise a lifecycle version (``1``, ``1.0``) to ``major.minor``."""
    major, minor = parse_semver(raw)
    return f"{major}.{minor}"


def _admitted(definition: VocabularyDefinition, revision: str) -> int:
    """How many keys a pin to *revision* admits."""
    return sum(
        1
        for entry in definition.entries.values()
        if VocabularyRevisionResolver.entry_active_at_pin(entry, revision)
    )


def _vocab_revisions(definition: VocabularyDefinition) -> list[dict[str, Any]]:
    """Each revision the key lifecycle defines, oldest first.

    A key's ``version`` opens the revision that introduces it and its
    ``removed`` the one that retires it; either is a contract a pin can name.
    """
    introduced: dict[str, int] = {}
    retired: dict[str, int] = {}
    for entry in definition.entries.values():
        version = _revision(entry.version)
        introduced[version] = introduced.get(version, 0) + 1
        if entry.removed:
            removed = _revision(entry.removed)
            retired[removed] = retired.get(removed, 0) + 1
    return [
        {
            "revision": revision,
            "introduced": introduced.get(revision, 0),
            "removed": retired.get(revision, 0),
            "admitted": _admitted(definition, revision),
        }
        for revision in sorted(set(introduced) | set(retired), key=parse_semver)
    ]


def _vocab_stages(definition: VocabularyDefinition) -> list[str]:
    stages = definition.metadata.get("stages", []) or []
    return [str(stage.get("id") or stage.get("name") or "") for stage in stages]


def _vocab_overview(name: str, definition: VocabularyDefinition) -> dict[str, Any]:
    """One row of ``info vocab``: the counts that need no pin lookup."""
    revisions = _vocab_revisions(definition)
    return {
        "name": name,
        "title": definition.metadata.name,
        "entries": len(definition.entries),
        "removed": sum(1 for entry in definition.entries.values() if entry.removed),
        "latest_revision": revisions[-1]["revision"] if revisions else None,
        "staged": bool(_vocab_stages(definition)),
    }


def _vocab_detail(name: str, definition: VocabularyDefinition) -> dict[str, Any]:
    """Everything ``info vocab <name>`` reports about one vocabulary."""
    from opentide.models.vocab_pins import all_pins

    revisions = _vocab_revisions(definition)
    defined = {item["revision"] for item in revisions}
    pins: list[dict[str, Any]] = []
    for schema_id, schema_pins in sorted(all_pins().items()):
        for path, contract in sorted(schema_pins.items()):
            try:
                pinned_vocab, revision = parse_vocab_contract(contract)
            except ValueError:
                continue
            if pinned_vocab != name:
                continue
            pins.append(
                {
                    "schema": schema_id,
                    "field": path,
                    "revision": revision,
                    "defined": revision in defined,
                    "admitted": _admitted(definition, revision),
                    "scoped": _field_is_scoped(schema_id, path),
                }
            )
    return {
        **_vocab_overview(name, definition),
        "key": definition.metadata.key,
        "stages": _vocab_stages(definition),
        "revisions": revisions,
        "pins": pins,
    }


def _field_is_scoped(schema_id: str, path: str) -> bool | None:
    """Whether the model field at *path* is declared ``VocabField(..., scoped=True)``.

    A pin may name a schema revision that has no model of its own
    (``objective::1.1``); the family's latest registered model stands in.
    ``None`` when no model declares the path.
    """
    from opentide.models.base import field_json_schema_extra
    from opentide.models.schema_registry import latest_model_for_family, resolve_model
    from opentide.models.version import SchemaVersion

    try:
        model: type[Any] | None = resolve_model(schema_id)
    except LookupError:
        try:
            model = latest_model_for_family(SchemaVersion.parse(schema_id).family)
        except (LookupError, ValueError):
            return None

    parts = path.split(".")
    for position, part in enumerate(parts):
        field = _model_field(model, part) if model is not None else None
        if field is None:
            return None
        if position == len(parts) - 1:
            return bool(field_json_schema_extra(field).get("tide.vocab.scoped"))
        model = _nested_model(field.annotation)
    return None


def _model_field(model: type[Any], name: str) -> Any:
    for field_name, field in model.model_fields.items():
        if name in (field_name, field.alias):
            return field
    return None


def _nested_model(annotation: Any) -> type[Any] | None:
    """The Tide model a field holds, looking through ``list[...]`` and ``... | None``."""
    from opentide.models.base import TideModel

    if isinstance(annotation, type) and issubclass(annotation, TideModel):
        return annotation
    if get_origin(annotation) in (list, tuple, Union, types.UnionType):
        for arg in get_args(annotation):
            nested = _nested_model(arg)
            if nested is not None:
                return nested
    return None


def _yes_no(value: bool | None) -> str:
    if value is None:
        return "?"
    return "yes" if value else "no"


def _vocab_list_table(vocabularies: list[dict[str, Any]]) -> Table:
    from rich.table import Table
    from rich.text import Text

    table = Table(title=f"Vocabularies ({len(vocabularies)})")
    table.add_column("Name", no_wrap=True)
    table.add_column("Entries", justify="right")
    table.add_column("Removed", justify="right")
    table.add_column("Latest revision")
    table.add_column("Staged")
    for vocab in vocabularies:
        table.add_row(
            Text(vocab["name"]),
            str(vocab["entries"]),
            str(vocab["removed"]),
            Text(vocab["latest_revision"] or "-"),
            _yes_no(vocab["staged"]),
        )
    return table


def _vocab_detail_tables(vocab: dict[str, Any]) -> list[Table]:
    """Summary, revisions and pins of one vocabulary, one table each."""
    from rich.table import Table
    from rich.text import Text

    summary = Table(title=f"Vocabulary {vocab['name']}")
    summary.add_column("Key")
    summary.add_column("Value", overflow="fold")
    summary.add_row("Title", Text(str(vocab["title"])))
    summary.add_row("Keyed by", Text(str(vocab["key"])))
    summary.add_row("Entries", str(vocab["entries"]))
    summary.add_row("Removed keys", str(vocab["removed"]))
    summary.add_row("Latest revision", Text(vocab["latest_revision"] or "-"))
    summary.add_row("Staged", _yes_no(vocab["staged"]))
    if vocab["stages"]:
        summary.add_row("Stages", Text(", ".join(vocab["stages"])))

    revisions = Table(title="Revisions")
    revisions.add_column("Revision")
    revisions.add_column("Introduced", justify="right")
    revisions.add_column("Removed", justify="right")
    revisions.add_column("Admitted", justify="right")
    for item in vocab["revisions"]:
        revisions.add_row(
            Text(item["revision"]),
            str(item["introduced"]),
            str(item["removed"]),
            str(item["admitted"]),
        )

    pins = Table(title="Pins")
    pins.add_column("Schema", no_wrap=True)
    pins.add_column("Field", overflow="fold")
    pins.add_column("Revision")
    pins.add_column("Admitted", justify="right")
    pins.add_column("Scoped")
    for pin in vocab["pins"]:
        revision = pin["revision"] if pin["defined"] else f"{pin['revision']} (undefined)"
        pins.add_row(
            Text(pin["schema"]),
            Text(pin["field"]),
            Text(revision),
            str(pin["admitted"]),
            _yes_no(pin["scoped"]),
        )
    if not vocab["pins"]:
        pins.caption = "No object schema pins this vocabulary"
    return [summary, revisions, pins]
