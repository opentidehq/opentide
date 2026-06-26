"""CLI entrypoint for documentation generation."""

from __future__ import annotations

import subprocess
from pathlib import Path

import structlog

from opentide.documentation.catalog import build_catalog
from opentide.documentation.config import load_settings
from opentide.documentation.context import DocumentationContext
from opentide.documentation.format.factory import formatter_for
from opentide.documentation.objects.objective import render_objective_page
from opentide.documentation.objects.rule import render_rule_page
from opentide.documentation.objects.threat import render_threat_page
from opentide.documentation.publish.index import write_index
from opentide.documentation.publish.paths import page_path, targets
from opentide.documentation.publish.writer import write_page
from opentide.documentation.types import DocumentScope
from opentide.generation import framework as fw

logger = structlog.get_logger("opentide.documentation.cli")

_OBJECT_KIND_TO_SCOPE = {
    "rule": DocumentScope.rules,
    "objective": DocumentScope.objectives,
    "threat": DocumentScope.threats,
}
_OBJECT_SCOPE_TO_KIND = {scope: kind for kind, scope in _OBJECT_KIND_TO_SCOPE.items()}


def _build_context(*, output: str | None = None, flavor: str | None = None) -> DocumentationContext:
    settings = load_settings(output=output, flavor=flavor)
    return DocumentationContext(
        flavor=settings.flavor,
        output_dir=settings.output_dir,
        formatter=formatter_for(settings.flavor),
        folder_index_pages=settings.folder_index_pages,
        uuid_permalinks=settings.uuid_permalinks,
        relations_direction=settings.relations_direction,
        index_relation_counts=settings.index_relation_counts,
        index_icons=settings.index_icons,
    )


def run_index(ctx: DocumentationContext) -> None:
    """Write folder and root index pages."""
    catalog = build_catalog()
    pub = targets(ctx)
    write_index(
        ctx,
        pub,
        rules=catalog.rules,
        objectives=catalog.objectives,
        threats=catalog.threats,
    )
    logger.info("index_written", output=str(ctx.output_dir))


def _git_stdout(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _resolve_merge_base(repo_root: Path) -> str:
    candidates: list[str] = []
    try:
        upstream = _git_stdout(repo_root, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}")
    except subprocess.CalledProcessError:
        upstream = ""
    if upstream:
        candidates.append(upstream)
    candidates.extend(["origin/development", "origin/main", "origin/master"])
    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            return _git_stdout(repo_root, "merge-base", "HEAD", candidate)
        except subprocess.CalledProcessError:
            continue
    return _git_stdout(repo_root, "merge-base", "HEAD", "HEAD")


def _git_changed_paths(repo_root: Path, merge_base: str) -> set[Path]:
    changed = _git_stdout(repo_root, "diff", "--name-only", "--diff-filter=ACMRD", merge_base)
    untracked = _git_stdout(repo_root, "ls-files", "--others", "--exclude-standard")
    lines = [line for line in changed.splitlines() if line] + [
        line for line in untracked.splitlines() if line
    ]
    return {Path(line) for line in lines}


def _object_uuid_and_name(body: object) -> tuple[str | None, str | None]:
    if not isinstance(body, dict):
        return None, None
    metadata = body.get("metadata")
    metadata_dict = metadata if isinstance(metadata, dict) else {}
    uuid = body.get("uuid") or metadata_dict.get("uuid")
    name = body.get("name") or metadata_dict.get("name")
    return (
        uuid if isinstance(uuid, str) and uuid else None,
        name if isinstance(name, str) and name else None,
    )


def _load_object_body(
    repo_root: Path, relative_path: Path, *, merge_base: str, absolute_path: Path
) -> object | None:
    from opentide.core.io import load_yaml, parse_yaml

    if absolute_path.exists():
        try:
            return load_yaml(absolute_path)
        except Exception:
            return None
    try:
        raw = _git_stdout(repo_root, "show", f"{merge_base}:{relative_path.as_posix()}")
    except subprocess.CalledProcessError:
        return None
    try:
        return parse_yaml(raw)
    except Exception:
        return None


def _changed_object_paths_and_uuids(
    repo_root: Path,
) -> tuple[set[Path], set[str], list[tuple[str, str, str]]]:
    """Return changed paths, live UUIDs, and deleted (kind, uuid, name) tuples."""
    from opentide.core.registry import OpenTide

    merge_base = _resolve_merge_base(repo_root)
    paths_cfg = OpenTide.Index["paths"]
    object_roots = {
        kind: Path(paths_cfg[kind]).resolve()
        for kind in _OBJECT_KIND_TO_SCOPE
        if kind in paths_cfg
    }
    changed_object_paths: set[Path] = set()
    changed_uuids: set[str] = set()
    deleted_objects: list[tuple[str, str, str]] = []
    for relative_path in _git_changed_paths(repo_root, merge_base):
        absolute_path = (repo_root / relative_path).resolve()
        if absolute_path.suffix.lower() != ".yaml":
            continue
        kind = next(
            (candidate for candidate, root in object_roots.items() if root in absolute_path.parents),
            None,
        )
        if kind is None:
            continue
        changed_object_paths.add(relative_path)
        body = _load_object_body(
            repo_root, relative_path, merge_base=merge_base, absolute_path=absolute_path
        )
        uuid, name = _object_uuid_and_name(body)
        if uuid is None:
            continue
        if absolute_path.exists():
            changed_uuids.add(uuid)
        elif name is not None:
            deleted_objects.append((kind, uuid, name))
    return changed_object_paths, changed_uuids, deleted_objects


def _expand_referrer_closure(changed_uuids: set[str]) -> set[str]:
    """Include upstream referrers so parent pages refresh when a child object changes."""
    closure = set(changed_uuids)
    for uuid in tuple(changed_uuids):
        try:
            relations = fw.relations_list(uuid, mode="flat", direction="upstream")
        except Exception:
            continue
        for related in relations.values():
            for related_uuid in related:
                kind = fw.get_type(related_uuid, mute=True)
                if kind in _OBJECT_KIND_TO_SCOPE:
                    closure.add(related_uuid)
    return closure


def _resolve_changed_targets(
    catalog_uuids: set[str], repo_root: Path
) -> tuple[set[Path], set[str], set[str], list[tuple[str, str, str]]]:
    changed_paths, changed_uuids, deleted_objects = _changed_object_paths_and_uuids(repo_root)
    closure = _expand_referrer_closure(changed_uuids)
    return changed_paths, changed_uuids, closure.intersection(catalog_uuids), deleted_objects


def _remove_deleted_pages(
    ctx: DocumentationContext, deleted_objects: list[tuple[str, str, str]]
) -> int:
    """Delete markdown pages for object YAMLs removed since the merge-base."""
    pub = targets(ctx)
    folder_for_kind = {
        "rule": pub.rules_dir,
        "objective": pub.objectives_dir,
        "threat": pub.threats_dir,
    }
    removed = 0
    for kind, uuid, name in deleted_objects:
        folder = folder_for_kind.get(kind)
        if folder is None:
            continue
        path = page_path(ctx, folder=folder, name=name, uuid=uuid)
        if path.exists():
            path.unlink()
            removed += 1
    return removed


def run_objects(
    ctx: DocumentationContext,
    scope: DocumentScope | None = None,
    *,
    target_uuids: set[str] | None = None,
) -> dict[str, int]:
    """Write object pages for one or all scopes."""
    catalog = build_catalog()
    pub = targets(ctx)
    counts: dict[str, int] = {"rules": 0, "objectives": 0, "threats": 0}

    if scope in (None, DocumentScope.threats):
        for record in catalog.threats:
            if target_uuids is not None and record.uuid not in target_uuids:
                continue
            write_page(
                page_path(ctx, folder=pub.threats_dir, name=record.name, uuid=record.uuid),
                render_threat_page(record.model, ctx, catalog),
            )
            counts["threats"] += 1

    if scope in (None, DocumentScope.objectives):
        for record in catalog.objectives:
            if target_uuids is not None and record.uuid not in target_uuids:
                continue
            write_page(
                page_path(ctx, folder=pub.objectives_dir, name=record.name, uuid=record.uuid),
                render_objective_page(record.model, ctx, catalog),
            )
            counts["objectives"] += 1

    if scope in (None, DocumentScope.rules):
        for record in catalog.rules:
            if target_uuids is not None and record.uuid not in target_uuids:
                continue
            write_page(
                page_path(ctx, folder=pub.rules_dir, name=record.name, uuid=record.uuid),
                render_rule_page(record.model, ctx, catalog),
            )
            counts["rules"] += 1

    return counts


def run(
    *,
    scope: str | None = None,
    output: str | None = None,
    flavor: str | None = None,
    changed: bool = False,
) -> dict[str, object]:
    """Run documentation generation for a scope or full pipeline."""
    ctx = _build_context(output=output, flavor=flavor)
    resolved = DocumentScope(scope) if scope else None

    if changed and resolved is not None:
        raise ValueError("--changed is only supported for full docs generation")

    if changed:
        catalog = build_catalog()
        catalog_records = [*catalog.rules, *catalog.objectives, *catalog.threats]
        catalog_uuids = {record.uuid for record in catalog_records}
        from opentide.core.root import get_repo_root

        changed_paths, changed_uuids, target_uuids, deleted_objects = _resolve_changed_targets(
            catalog_uuids, get_repo_root()
        )
        if not changed_paths:
            return {
                "message": "No changed object documentation detected",
                "changed_paths": [],
                "changed_uuids": [],
                "counts": {"rules": 0, "objectives": 0, "threats": 0},
                "output": str(ctx.output_dir),
            }
        counts = run_objects(ctx, target_uuids=target_uuids)
        removed = _remove_deleted_pages(ctx, deleted_objects)
        run_index(ctx)
        touched_scopes = {
            _OBJECT_SCOPE_TO_KIND[record.object_type]
            for record in catalog_records
            if record.uuid in target_uuids
        }
        return {
            "message": "Changed documentation pipeline completed",
            "counts": counts,
            "removed": removed,
            "changed_paths": sorted(str(path) for path in changed_paths),
            "changed_uuids": sorted(changed_uuids),
            "targets": sorted(target_uuids),
            "scopes": sorted(touched_scopes),
            "output": str(ctx.output_dir),
        }

    if resolved is DocumentScope.index:
        run_index(ctx)
        return {"message": "Index pages written", "output": str(ctx.output_dir)}

    counts = run_objects(ctx, resolved)
    if resolved is None:
        run_index(ctx)
        return {
            "message": "Full documentation pipeline completed",
            "counts": counts,
            "output": str(ctx.output_dir),
        }

    return {"message": f"Documentation scope {resolved.value} completed", "counts": counts}
