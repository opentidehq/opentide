"""Explorer static-site export bundle generation."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from opentide.core.logging import get_logger
from opentide.core.registry import OpenTide
from opentide.generation.framework import techniques_resolver

logger = get_logger(__name__)


def _infer_type(body: dict[str, Any]) -> str | None:
    schema = (body.get("metadata") or {}).get("schema")
    if isinstance(schema, str):
        return schema.split("::")[0]
    if body.get("configurations"):
        return "rule"
    if body.get("objective"):
        return "objective"
    if body.get("threat"):
        return "threat"
    if body.get("signal") or body.get("parent"):
        return "signal"
    return None


def _platforms(body: dict[str, Any], obj_type: str) -> list[str]:
    if obj_type != "rule":
        return []
    configs = body.get("configurations") or {}
    return [key.replace("_", " ") for key in configs]


def _status(body: dict[str, Any], obj_type: str) -> str | None:
    if obj_type != "rule":
        return None
    configs = body.get("configurations") or {}
    statuses = [str(cfg.get("status", "")).upper() for cfg in configs.values()]
    if "PRODUCTION" in statuses:
        return "PRODUCTION"
    if "STAGING" in statuses:
        return "STAGING"
    return statuses[0] if statuses else None


def _actors(body: dict[str, Any], obj_type: str) -> list[str]:
    if obj_type != "threat":
        return []
    threat = body.get("threat") or {}
    actors = threat.get("actors") or body.get("actors") or []
    return [str(a) for a in actors if isinstance(a, str)]


def _count_relations(uuid: str, flat_index: dict[str, dict[str, Any]]) -> int:
    body = flat_index[uuid]
    obj_type = _infer_type(body)
    count = 0
    if obj_type == "objective":
        count += len((body.get("objective") or {}).get("threats") or [])
    if obj_type in {"signal", "rule"}:
        parent = body.get("parent") or body.get("detection_model")
        if parent:
            count += 1
    for other in flat_index.values():
        other_type = _infer_type(other)
        if other_type == "objective" and uuid in (
            (other.get("objective") or {}).get("threats") or []
        ):
            count += 1
        if other_type in {"signal", "rule"} and uuid in {
            other.get("parent"),
            other.get("detection_model"),
        }:
            count += 1
    return count


def build_staging_index(models: dict[str, dict[str, Any]]) -> dict[str, Any]:
    deployments: dict[str, dict[str, str]] = {}
    platform_summary: dict[str, dict[str, int]] = {}
    staging_objects: set[str] = set()
    production_objects: set[str] = set()

    for uuid, body in models.get("rule", {}).items():
        configs = body.get("configurations") or {}
        deployments[uuid] = {}
        for platform, config in configs.items():
            status = str(config.get("status", "UNKNOWN")).upper()
            deployments[uuid][platform] = status
            summary = platform_summary.setdefault(
                platform, {"production": 0, "staging": 0, "other": 0}
            )
            if status == "PRODUCTION":
                summary["production"] += 1
                production_objects.add(uuid)
            elif status == "STAGING":
                summary["staging"] += 1
                staging_objects.add(uuid)
            else:
                summary["other"] += 1

    return {
        "deployments": deployments,
        "platformSummary": platform_summary,
        "stagingObjects": sorted(staging_objects),
        "productionObjects": sorted(production_objects),
    }


def build_chaining_index(threats: dict[str, Any]) -> dict[str, dict[str, list[str]]]:
    chaining: dict[str, dict[str, list[str]]] = {}
    for threat in threats.values():
        if not isinstance(threat, dict):
            continue
        uuid = (threat.get("metadata") or {}).get("uuid")
        links = (threat.get("threat") or {}).get("chaining") or []
        if not uuid or not links:
            continue
        chaining.setdefault(uuid, {})
        for link in links:
            if not isinstance(link, dict):
                continue
            relation = link.get("relation")
            vector = link.get("vector")
            if not relation or not vector:
                continue
            chaining[uuid].setdefault(relation, [])
            if vector not in chaining[uuid][relation]:
                chaining[uuid][relation].append(vector)
    return chaining


def build_search_documents(
    summaries: list[dict[str, Any]], flat_index: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    documents = []
    for summary in summaries:
        uuid = summary["uuid"]
        body = flat_index.get(uuid, {})
        documents.append(
            {
                "id": uuid,
                "uuid": uuid,
                "type": summary["type"],
                "name": summary["name"],
                "techniques": summary.get("techniques", []),
                "actors": summary.get("actors", []),
                "platforms": summary.get("platforms", []),
                "status": summary.get("status") or "",
                "relatedCount": summary.get("relatedCount", 0),
                "content": json.dumps(body)[:4000],
            }
        )
    return documents


class ExplorerExport:
    """Build explorer.bundle.json and explorer.search.json for the static UI."""

    def __init__(self, export_dir: Path | None = None) -> None:
        self.export_dir = export_dir or Path(OpenTide.Configurations.Global.Paths.Tide.exports)

    def build_bundle(self) -> dict[str, Any]:
        OpenTide.initialise()
        models = {
            "threat": dict(OpenTide.Models.threats),
            "objective": dict(OpenTide.Models.objectives),
            "signal": dict(getattr(OpenTide.Models, "signals", {}) or {}),
            "rule": dict(OpenTide.Models.rules),
        }
        flat_index: dict[str, dict[str, Any]] = {}
        for bucket in models.values():
            flat_index.update(bucket)

        chaining = build_chaining_index(models["threat"])
        staging_index = build_staging_index(models)

        summaries: list[dict[str, Any]] = []
        for uuid, body in flat_index.items():
            obj_type = _infer_type(body)
            if not obj_type:
                continue
            summaries.append(
                {
                    "uuid": uuid,
                    "type": obj_type,
                    "name": body.get("name") or uuid,
                    "schema": (body.get("metadata") or {}).get("schema"),
                    "version": (body.get("metadata") or {}).get("version"),
                    "tlp": (body.get("metadata") or {}).get("tlp"),
                    "status": _status(body, obj_type),
                    "techniques": techniques_resolver(uuid),
                    "actors": _actors(body, obj_type),
                    "relatedCount": _count_relations(uuid, flat_index),
                    "platforms": _platforms(body, obj_type),
                }
            )

        signals = {
            uuid: body for uuid, body in models["signal"].items() if isinstance(body, dict)
        }

        return {
            "version": "0.1.0",
            "generatedAt": datetime.now(UTC).isoformat(),
            "models": models,
            "flatIndex": flat_index,
            "chaining": chaining,
            "signals": signals,
            "summaries": summaries,
            "stagingIndex": staging_index,
        }

    def export(self) -> tuple[Path, Path]:
        self.export_dir.mkdir(parents=True, exist_ok=True)
        bundle = self.build_bundle()
        bundle_path = self.export_dir / "explorer.bundle.json"
        search_path = self.export_dir / "explorer.search.json"
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
        search_path.write_text(
            json.dumps({"documents": build_search_documents(bundle["summaries"], bundle["flatIndex"])}),
            encoding="utf-8",
        )
        logger.info(
            "Wrote explorer exports to %s (%d objects)",
            self.export_dir,
            len(bundle["summaries"]),
        )
        return bundle_path, search_path


def export_explorer_bundle(export_dir: Path | None = None) -> tuple[Path, Path]:
    return ExplorerExport(export_dir=export_dir).export()
