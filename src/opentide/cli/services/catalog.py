"""``opentide info catalog``: every object, how they relate, and the ATT&CK skeleton.

One document feeds an editor's catalogue, coverage graph, ATT&CK matrix and
search. It is built in one pass over the registry the rest of ``info`` already
loaded: each edge comes from the field that holds the reference, so the cost is
linear in the catalogue. The per-object graphs in
:mod:`opentide.documentation.catalog` (``coverage_graph``, ``chaining_network``)
answer "what surrounds this object" with a scan of the catalogue each, which
over every object is quadratic; this module reads the same fields and uses the
same edge names (``covers``, ``implements``) instead.

Inherited techniques follow :func:`opentide.generation.framework.techniques_resolver`
(:func:`_inherited_techniques`), chains come from the registry's memoised chaining
index (:mod:`opentide.core.chaining`).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from opentide.core.logging import get_logger
from opentide.core.object_fields import object_role_values
from opentide.models.base import FieldRole

logger = get_logger(__name__)

#: Object families, in the order the document lists them.
FAMILIES = ("threat", "objective", "rule")

#: Every ``kind`` an edge can have.
EDGE_KINDS = ("covers", "implements", "parent", "chains", "technique", "logsource")

#: Name prefixes of the ATT&CK keys that are not Enterprise techniques.
_NON_ENTERPRISE = ("Mobile : ", "Industrial : ")

_NAME_LINE = re.compile(r"^name[ \t]*:", re.MULTILINE)
_UUID_LINE = re.compile(r"^[ \t]+uuid[ \t]*:[ \t]*['\"]?([0-9A-Fa-f-]{32,36})", re.MULTILINE)
_SCHEMA_LINE = re.compile(r"^[ \t]+schema[ \t]*:[ \t]*['\"]?([\w:.]+)", re.MULTILINE)
_NAME_VALUE = re.compile(r"^name[ \t]*:[ \t]*['\"]?([^'\"\r\n#]+)", re.MULTILINE)


def collect_catalog(workspace: Path, parse_errors: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """The ``objects``, ``edges``, ``signals``, ``attack`` and catalogue counts.

    Reads the registry as loaded: call it after ``Opentide.reload()``.
    *parse_errors* are the registry's files that did not load; each becomes an
    object row with a ``load_error``.
    """
    from opentide.core.index_manager import IndexManager
    from opentide.core.registry import Opentide

    index = IndexManager.load()
    models: Mapping[str, Any] = index.get("objects") or {}
    file_paths: Mapping[str, str] = index.get("file_paths") or {}
    threats: Mapping[str, Any] = models.get("threat") or {}
    objectives: Mapping[str, Any] = models.get("objective") or {}
    rules: Mapping[str, Any] = models.get("rule") or {}
    signals: Mapping[str, Any] = models.get("signal") or {}

    definition, pinned = _attack_definition()
    entries = _enterprise_entries(definition, pinned)
    attack = _attack_skeleton(definition, entries)
    stage_of = _technique_tactics(entries)
    strategies = _status_strategies(Opentide.Configurations.Deployment.Index)
    deployment = _deployment_bindings(workspace)
    threat_actors = {
        uuid: [value for _, value in object_role_values(body, FieldRole.ACTORS)]
        for uuid, body in threats.items()
    }
    tactic_order = {tactic["shortname"]: n for n, tactic in enumerate(attack["tactics"])}

    objects: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    def edge(source: str, target: str, kind: str, field_path: str, **extra: Any) -> None:
        edges.append(
            {
                "from": source,
                "to": target,
                "kind": kind,
                "field_path": field_path,
                "relation": extra.get("relation"),
                "missing": bool(extra.get("missing", False)),
            }
        )

    chaining: Mapping[str, Mapping[str, list[str]]] = Opentide.Models.chaining or {}
    for family, bucket in (("threat", threats), ("objective", objectives), ("rule", rules)):
        rows = []
        for uuid, body in bucket.items():
            if not isinstance(body, Mapping):
                continue
            own = object_role_values(body, FieldRole.TECHNIQUES)
            own_ids = [technique for _, technique in own]
            inherited = [
                t
                for t in _inherited_techniques(family, body, threats, objectives, signals)
                if t not in own_ids
            ]
            tactics = sorted(
                {tactic for t in (*own_ids, *inherited) for tactic in stage_of.get(t, ())},
                key=lambda name: tactic_order.get(name, len(tactic_order)),
            )
            parents = _parent_threats(uuid, family, body, objectives, signals)
            actors = list(
                dict.fromkeys(
                    actor for threat in parents for actor in threat_actors.get(threat, ())
                )
            )
            rows.append(
                _object_row(
                    uuid,
                    family,
                    body,
                    workspace,
                    file_paths.get(uuid),
                    techniques={"own": own_ids, "inherited": inherited},
                    tactics=tactics,
                    actors=actors,
                    platforms=_platform_blocks(body, strategies) if family == "rule" else [],
                    deployment=deployment.get(_canonical(uuid), []),
                )
            )
            for field_path, technique in own:
                edge(uuid, technique, "technique", field_path)
            if family == "threat":
                for relation, targets in (chaining.get(uuid) or {}).items():
                    for target in targets:
                        edge(
                            uuid,
                            target,
                            "chains",
                            "threat.chaining",
                            relation=relation,
                            missing=target not in threats,
                        )
            elif family == "objective":
                _objective_edges(uuid, body, threats, signals, edge)
            else:
                target = body.get("detection_model")
                if isinstance(target, str) and target.strip():
                    edge(
                        uuid,
                        target,
                        "implements",
                        "detection_model",
                        missing=target not in objectives and target not in signals,
                    )
        rows.sort(key=lambda row: row["path"] or "")
        objects.extend(rows)

    load_errors = [_load_error_row(entry, workspace) for entry in parse_errors]
    objects.extend(load_errors)

    signal_rows = [
        {
            "uuid": str(uuid),
            "name": str(body.get("name") or ""),
            "objective": body.get("owner"),
            "parent": body.get("parent") or None,
        }
        for uuid, body in signals.items()
        if isinstance(body, Mapping)
    ]
    return {
        "objects": objects,
        "edges": edges,
        "signals": signal_rows,
        "attack": attack,
        "catalog_summary": {
            "objects": len(objects),
            "threats": len(threats),
            "objectives": len(objectives),
            "rules": len(rules),
            "signals": len(signal_rows),
            "edges": len(edges),
            "load_errors": len(load_errors),
        },
    }


# --------------------------------------------------------------------------- objects


def _object_row(
    uuid: str,
    family: str,
    body: Mapping[str, Any],
    workspace: Path,
    file_path: str | None,
    **fields: Any,
) -> dict[str, Any]:
    metadata = body.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    path, absolute = _paths(file_path, workspace)
    return {
        "uuid": str(uuid),
        "type": family,
        "schema": _text(metadata.get("schema")),
        "name": _text(body.get("name")) or "",
        "path": path,
        "file_path": absolute,
        "line": _name_line(Path(file_path)) if file_path else 1,
        "tlp": _text(metadata.get("tlp")),
        "author": _text(metadata.get("author")),
        "created": _text(metadata.get("created")),
        "modified": _text(metadata.get("modified")),
        "reviewed": _text(metadata.get("reviewed")),
        **fields,
        "load_error": None,
    }


def _load_error_row(entry: Mapping[str, Any], workspace: Path) -> dict[str, Any]:
    """A file the registry could not load: what can be read of it, and why it failed."""
    raw_path = str(entry.get("path") or "")
    path, absolute = _paths(raw_path or None, workspace)
    text = _read(Path(raw_path)) if raw_path else None
    code = str(entry.get("code") or "yaml_parse")
    line: int | None = None
    if code == "yaml_parse" and text is not None:
        line = _yaml_problem_line(text)
    message = entry.get("message") or (
        f"Could not parse object YAML: {entry.get('error') or 'unknown error'}"
    )

    def found(pattern: re.Pattern[str]) -> str | None:
        match = pattern.search(text) if text else None
        return match.group(1).strip() if match else None

    return {
        "uuid": found(_UUID_LINE),
        "type": str(entry.get("object_type") or "") or None,
        "schema": found(_SCHEMA_LINE),
        "name": found(_NAME_VALUE) or (Path(raw_path).stem if raw_path else ""),
        "path": path,
        "file_path": absolute,
        "line": _line_of(text, _NAME_LINE) if text else 1,
        "tlp": None,
        "author": None,
        "created": None,
        "modified": None,
        "reviewed": None,
        "platforms": [],
        "deployment": [],
        "techniques": {"own": [], "inherited": []},
        "tactics": [],
        "actors": [],
        "load_error": {"code": code, "message": str(message), "line": line},
    }


def _paths(file_path: str | None, workspace: Path) -> tuple[str | None, str | None]:
    """Workspace-relative path with forward slashes, and the absolute path."""
    if not file_path:
        return None, None
    path = Path(file_path)
    absolute = path if path.is_absolute() else workspace / path
    for base, candidate in ((workspace, absolute), (workspace.resolve(), absolute.resolve())):
        try:
            return candidate.relative_to(base).as_posix(), str(absolute)
        except ValueError:
            continue
    return absolute.as_posix(), str(absolute)


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return None


def _line_of(text: str, pattern: re.Pattern[str]) -> int:
    match = pattern.search(text)
    return text.count("\n", 0, match.start()) + 1 if match else 1


def _name_line(path: Path) -> int:
    """1-based line of the root ``name:`` key, or 1."""
    text = _read(path)
    return _line_of(text, _NAME_LINE) if text else 1


def _yaml_problem_line(text: str) -> int | None:
    import yaml

    from opentide.core.io import describe_yaml_error, parse_yaml

    try:
        parse_yaml(text)
    except yaml.YAMLError as exc:
        return describe_yaml_error(exc).line
    except Exception:
        return None
    return None


def _text(value: Any) -> str | None:
    if value is None or value == "":
        return None
    return str(value)


def _canonical(uuid: str) -> str:
    return str(uuid).strip().lower()


# --------------------------------------------------------------------------- relations


def _objective_edges(
    uuid: str,
    body: Mapping[str, Any],
    threats: Mapping[str, Any],
    signals: Mapping[str, Any],
    edge: Any,
) -> None:
    """``covers`` to each threat, and each of its signals' ``parent`` and ``logsource``."""
    section = body.get("objective")
    section = section if isinstance(section, Mapping) else {}
    for threat in _as_list(section.get("threats")):
        if isinstance(threat, str) and threat:
            edge(uuid, threat, "covers", "objective.threats", missing=threat not in threats)
    for position, signal in enumerate(section.get("signals") or ()):
        if not isinstance(signal, Mapping):
            continue
        signal_uuid = signal.get("uuid")
        indexed = signals.get(str(signal_uuid)) if signal_uuid else None
        # A signal UUID another objective defined first is indexed under that one.
        if not isinstance(indexed, Mapping) or indexed.get("owner") != uuid:
            continue
        prefix = f"objective.signals.{position}"
        parent = signal.get("parent")
        if isinstance(parent, str) and parent:
            edge(
                str(signal_uuid),
                parent,
                "parent",
                f"{prefix}.parent",
                missing=parent not in signals,
            )
        data = signal.get("data")
        logsources = data.get("logsources") if isinstance(data, Mapping) else None
        for name in _as_list(logsources):
            if isinstance(name, str) and name:
                edge(str(signal_uuid), name, "logsource", f"{prefix}.data.logsources")


def _parent_threats(
    uuid: str,
    family: str,
    body: Mapping[str, Any],
    objectives: Mapping[str, Any],
    signals: Mapping[str, Any],
) -> list[str]:
    """The threats whose actors an object carries: itself, or those its objective covers."""
    if family == "threat":
        return [uuid]
    if family == "rule":
        target = body.get("detection_model")
        if not isinstance(target, str):
            return []
        signal = signals.get(target)
        owner = signal.get("owner") if isinstance(signal, Mapping) else target
        objective = objectives.get(owner) if isinstance(owner, str) else None
        if not isinstance(objective, Mapping):
            return []
        body = objective
    section = body.get("objective")
    threats = section.get("threats") if isinstance(section, Mapping) else None
    return [threat for threat in _as_list(threats) if isinstance(threat, str)]


def _as_list(value: Any) -> list[Any]:
    """A field that holds a list, read as one: ``[value]`` for a lone string.

    An author who writes ``threats: <uuid>`` or ``logsources: Windows`` means one
    item; iterating the string would make one per character.
    """
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple)):
        return list(value)
    return []


def _techniques(body: Any) -> list[str]:
    return [technique for _, technique in object_role_values(body, FieldRole.TECHNIQUES)]


def _objective_techniques(body: Any, threats: Mapping[str, Any]) -> list[str]:
    """An objective's techniques: its own, else those of each threat it covers that exists."""
    own = _techniques(body)
    if own:
        return own
    section = body.get("objective") if isinstance(body, Mapping) else None
    covered = _as_list(section.get("threats")) if isinstance(section, Mapping) else []
    found: list[str] = []
    for threat in covered:
        parent = threats.get(threat) if isinstance(threat, str) else None
        # A dangling threat: its covers edge says so (missing: true); the others still count.
        if isinstance(parent, Mapping):
            found.extend(_techniques(parent))
    return list(dict.fromkeys(found))


def _inherited_techniques(
    family: str,
    body: Mapping[str, Any],
    threats: Mapping[str, Any],
    objectives: Mapping[str, Any],
    signals: Mapping[str, Any],
) -> list[str]:
    """What an object gets from its parents, as ``techniques_resolver`` resolves it.

    A rule takes its objective's (through a signal's owner), an objective its
    threats'; a threat has no parent. Resolved here rather than by
    ``techniques_resolver``, which gives up on the first missing parent and
    iterates a lone string per character.
    """
    if family == "objective":
        return _objective_techniques(body, threats)
    if family != "rule":
        return []
    target = body.get("detection_model")
    if not isinstance(target, str):
        return []
    signal = signals.get(target)
    owner = signal.get("owner") if isinstance(signal, Mapping) else target
    objective = objectives.get(owner) if isinstance(owner, str) else None
    if not isinstance(objective, Mapping):
        return []
    return _objective_techniques(objective, threats)


def _platform_blocks(
    body: Mapping[str, Any], strategies: Mapping[str, str]
) -> list[dict[str, Any]]:
    blocks = body.get("configurations")
    if not isinstance(blocks, Mapping):
        return []
    rows: list[dict[str, Any]] = []
    for platform, block in blocks.items():
        if not isinstance(block, Mapping):
            continue
        status = _text(block.get("status"))
        rows.append(
            {
                "id": str(platform),
                "enabled": block.get("enabled") is True,
                "status": status,
                "strategy": strategies.get(status) if status else None,
            }
        )
    return rows


def _status_strategies(deployment: Mapping[str, Any]) -> dict[str, str]:
    """Status name to strategy name, from ``deployment.toml`` as written."""
    from opentide.models.deployment_enums import StatusStrategy

    result: dict[str, str] = {}
    for entry in deployment.get("statuses") or ():
        if not isinstance(entry, Mapping):
            continue
        name, strategy = entry.get("name"), entry.get("strategy")
        strategy = getattr(strategy, "name", strategy)
        if (
            isinstance(name, str)
            and isinstance(strategy, str)
            and strategy.upper() in StatusStrategy.__members__
        ):
            result[name] = strategy.upper()
    return result


def _deployment_bindings(workspace: Path) -> dict[str, list[dict[str, Any]]]:
    """Each rule's ``{platform, tenant, deployed, rule_id}`` from ``.opentide/states/deployment/``.

    The directory is listed once. A shard that does not parse is skipped here;
    ``opentide validate`` reports it.
    """
    from opentide.states.deployment import (
        DeploymentState,
        DeploymentStateError,
        deployment_state_dir,
    )

    directory = deployment_state_dir(workspace)
    try:
        shards = sorted(directory.glob("*.json"))
    except OSError:
        return {}
    bindings: dict[str, list[dict[str, Any]]] = {}
    for shard in shards:
        try:
            state = DeploymentState.from_file(shard)
        except DeploymentStateError as exc:
            logger.debug("deployment_state_skipped", path=str(shard), detail=str(exc))
            continue
        bindings[_canonical(state.object_uuid)] = [
            {"platform": platform, "tenant": tenant, "deployed": True, "rule_id": external_id}
            for platform, tenant, external_id in state.bindings()
        ]
    return bindings


# --------------------------------------------------------------------------- ATT&CK


def _attack_definition() -> tuple[Any, str | None]:
    """The ``att&ck`` vocabulary and the newest revision an object schema pins it to."""
    from opentide.core.registry import Opentide
    from opentide.generation.vocabulary import parse_semver, parse_vocab_contract
    from opentide.models.vocab_pins import all_pins

    definition = Opentide.Vocabularies.Index.get("att&ck")
    revisions: list[str] = []
    for schema_pins in all_pins().values():
        for contract in schema_pins.values():
            try:
                vocab, revision = parse_vocab_contract(contract)
            except ValueError:
                continue
            if vocab == "att&ck":
                revisions.append(revision)
    pinned = max(revisions, key=parse_semver) if revisions else None
    return definition, pinned


def _enterprise_entries(definition: Any, pinned: str | None) -> dict[str, Any]:
    """Enterprise technique entries the pinned revision admits, by id."""
    from opentide.generation.vocabulary import VocabularyRevisionResolver

    if definition is None:
        return {}
    return {
        str(key): entry
        for key, entry in definition.entries.items()
        if not str(entry.name).startswith(_NON_ENTERPRISE)
        and (pinned is None or VocabularyRevisionResolver.entry_active_at_pin(entry, pinned))
    }


def _shortname(tactic: str) -> str:
    return tactic.strip().lower().replace(" ", "-")


def _technique_tactics(entries: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
    """Each technique id to the shortnames of its tactics."""
    from opentide.platforms.elastic.attack import TACTIC_MAP

    result: dict[str, tuple[str, ...]] = {}
    for key, entry in entries.items():
        names = []
        for stage in entry.stages:
            mapped = TACTIC_MAP.get(str(stage).strip().lower())
            names.append(_shortname(mapped[0] if mapped else str(stage)))
        result[key] = tuple(dict.fromkeys(names))
    return result


def _attack_skeleton(definition: Any, entries: Mapping[str, Any]) -> dict[str, Any]:
    """The Enterprise matrix: tactics in order, and every technique with its name and family."""
    from opentide.platforms.elastic.attack import TACTIC_MAP, TACTIC_ORDER

    techniques: dict[str, dict[str, Any]] = {}
    for key in sorted(entries):
        parent = key.split(".", 1)[0] if "." in key else None
        techniques[key] = {"name": "", "parent": parent, "subtechniques": []}
    for key, row in techniques.items():
        name = str(entries[key].name)
        parent = row["parent"]
        if parent is not None:
            parent_name = str(entries[parent].name) if parent in entries else ""
            # "OS Credential Dumping: LSASS Memory" is listed under its parent as "LSASS Memory".
            if parent_name and name.startswith(f"{parent_name}: "):
                name = name[len(parent_name) + 2 :]
            if parent in techniques:
                techniques[parent]["subtechniques"].append(key)
            else:
                row["parent"] = None
        row["name"] = name

    stages: list[str] = []
    if definition is not None:
        for stage in definition.metadata.get("stages", []) or []:
            name = stage.get("name") or stage.get("id") if isinstance(stage, Mapping) else stage
            if name:
                stages.append(str(name))
    if not stages:
        stages = [name for name, _ in TACTIC_ORDER]
    tactics: list[dict[str, Any]] = []
    by_name: dict[str, dict[str, Any]] = {}
    for stage in stages:
        mapped = TACTIC_MAP.get(stage.strip().lower())
        name, tactic_id = mapped or (stage, None)
        if name in by_name:
            continue
        row = {"id": tactic_id, "shortname": _shortname(name), "name": name, "techniques": []}
        by_name[name] = row
        tactics.append(row)
    for key in sorted(techniques, key=lambda item: techniques[item]["name"].lower()):
        if techniques[key]["parent"] is not None:
            continue
        for stage in entries[key].stages:
            mapped = TACTIC_MAP.get(str(stage).strip().lower())
            tactic = by_name.get(mapped[0] if mapped else str(stage))
            if tactic is not None and key not in tactic["techniques"]:
                tactic["techniques"].append(key)
    return {"tactics": tactics, "techniques": techniques}
