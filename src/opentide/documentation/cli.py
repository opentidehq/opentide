"""CLI entrypoint for documentation generation."""

from __future__ import annotations

import subprocess
from collections.abc import Mapping, Set
from pathlib import Path
from typing import Literal

import structlog

from opentide.documentation.catalog import build_catalog
from opentide.documentation.config import load_settings
from opentide.documentation.context import DocumentationContext
from opentide.documentation.format.factory import formatter_for
from opentide.documentation.markdown.links import page_slug
from opentide.documentation.objects.objective import render_objective_page
from opentide.documentation.objects.rule import render_rule_page
from opentide.documentation.objects.threat import render_threat_page
from opentide.documentation.publish.index import write_index
from opentide.documentation.publish.paths import page_path, targets
from opentide.documentation.publish.prune import OBJECT_SCOPES, prune_stale_pages
from opentide.documentation.publish.writer import write_page
from opentide.documentation.types import DocumentScope
from opentide.generation import framework as fw
from opentide.generation.errors import rendering

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


def _baseline_body(repo_root: Path, relative_path: Path, *, merge_base: str) -> object | None:
    from opentide.core.io import parse_yaml

    try:
        raw = _git_stdout(repo_root, "show", f"{merge_base}:{relative_path.as_posix()}")
    except (subprocess.CalledProcessError, OSError):
        # OSError covers git missing from PATH; the object simply has no
        # baseline revision to read, which is the same outcome as a failed show.
        return None
    try:
        return parse_yaml(raw)
    except Exception:
        return None


def _load_object_body(
    repo_root: Path, relative_path: Path, *, merge_base: str, absolute_path: Path
) -> object | None:
    from opentide.core.io import load_yaml

    if absolute_path.exists():
        try:
            return load_yaml(absolute_path)
        except Exception:
            return None
    return _baseline_body(repo_root, relative_path, merge_base=merge_base)


def _changed_object_paths_and_uuids(
    repo_root: Path,
) -> tuple[set[Path], set[str], dict[str, str]]:
    """Return changed paths, live UUIDs, and each changed object's baseline name.

    The baseline names come from the merge-base revision of every changed path,
    deleted or not, so a caller can tell which objects were renamed.
    """
    from opentide.core.git_baseline import changed_paths, resolve_baseline
    from opentide.core.registry import Opentide

    baseline = resolve_baseline(repo_root)
    merge_base = baseline.commit
    paths_cfg = Opentide.Index["paths"]
    object_roots = {
        kind: Path(paths_cfg[kind]).resolve() for kind in _OBJECT_KIND_TO_SCOPE if kind in paths_cfg
    }
    changed_object_paths: set[Path] = set()
    changed_uuids: set[str] = set()
    previous_names: dict[str, str] = {}
    for change in changed_paths(repo_root, baseline):
        relative_path = change.relative
        absolute_path = change.absolute.resolve()
        if absolute_path.suffix.lower() != ".yaml":
            continue
        kind = next(
            (
                candidate
                for candidate, root in object_roots.items()
                if root in absolute_path.parents
            ),
            None,
        )
        if kind is None:
            continue
        changed_object_paths.add(relative_path)
        body = _load_object_body(
            repo_root, relative_path, merge_base=merge_base, absolute_path=absolute_path
        )
        uuid, name = _object_uuid_and_name(body)
        if absolute_path.exists():
            if uuid is not None:
                changed_uuids.add(uuid)
            uuid, name = _object_uuid_and_name(
                _baseline_body(repo_root, relative_path, merge_base=merge_base)
            )
        if uuid is not None and name is not None:
            previous_names[uuid] = name
    return changed_object_paths, changed_uuids, previous_names


def _expand_referrer_closure(changed_uuids: Set[str], renamed: Set[str] = frozenset()) -> set[str]:
    """Include the referrers whose pages must be rewritten for *changed_uuids*.

    Upstream referrers refresh so parent pages show a changed child. A renamed
    object's page moves, so its downstream referrers are rewritten too, or they
    keep linking the old page.
    """
    closure = set(changed_uuids)
    walks: list[tuple[str, Literal["upstream", "downstream"]]] = [
        (uuid, "upstream") for uuid in sorted(changed_uuids)
    ]
    walks += [(uuid, "downstream") for uuid in sorted(renamed)]
    for uuid, direction in walks:
        try:
            relations = fw.relations_list(uuid, mode="flat", direction=direction)
        except Exception:
            continue
        for related in relations.values():
            for related_uuid in related:
                kind = fw.get_type(related_uuid, mute=True)
                if kind in _OBJECT_KIND_TO_SCOPE:
                    closure.add(related_uuid)
    return closure


def _resolve_changed_targets(
    catalog_names: Mapping[str, str], repo_root: Path
) -> tuple[set[Path], set[str], set[str]]:
    """Return changed paths, changed UUIDs, and the catalogue UUIDs to rewrite."""
    changed_paths, changed_uuids, previous_names = _changed_object_paths_and_uuids(repo_root)
    renamed = {
        uuid for uuid, name in previous_names.items() if catalog_names.get(uuid, name) != name
    }
    closure = _expand_referrer_closure(changed_uuids, renamed)
    return changed_paths, changed_uuids, closure.intersection(catalog_names)


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
            with rendering(record.uuid):
                write_page(
                    page_path(
                        ctx,
                        folder=pub.threats_dir,
                        name=record.name,
                        uuid=record.uuid,
                        slug=page_slug(record),
                    ),
                    render_threat_page(record.model, ctx, catalog),
                )
            counts["threats"] += 1

    if scope in (None, DocumentScope.objectives):
        for record in catalog.objectives:
            if target_uuids is not None and record.uuid not in target_uuids:
                continue
            with rendering(record.uuid):
                write_page(
                    page_path(
                        ctx,
                        folder=pub.objectives_dir,
                        name=record.name,
                        uuid=record.uuid,
                        slug=page_slug(record),
                    ),
                    render_objective_page(record.model, ctx, catalog),
                )
            counts["objectives"] += 1

    if scope in (None, DocumentScope.rules):
        for record in catalog.rules:
            if target_uuids is not None and record.uuid not in target_uuids:
                continue
            with rendering(record.uuid):
                write_page(
                    page_path(
                        ctx,
                        folder=pub.rules_dir,
                        name=record.name,
                        uuid=record.uuid,
                        slug=page_slug(record),
                    ),
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
        catalog_names = {record.uuid: record.name for record in catalog_records}
        from opentide.core.git_baseline import GitBaselineError
        from opentide.registry.discovery import discover_workspace

        try:
            changed_paths, changed_uuids, target_uuids = _resolve_changed_targets(
                catalog_names, discover_workspace()
            )
        except GitBaselineError as exc:
            logger.warning("docs_changed_requires_git", detail=str(exc))
            return {
                "message": f"--changed requires a git repository: {exc}",
                "status": "failed",
                "changed_paths": [],
                "changed_uuids": [],
                "counts": {"rules": 0, "objectives": 0, "threats": 0},
                "output": str(ctx.output_dir),
                "_exit_code": 1,
            }
        if not changed_paths:
            return {
                "message": "No changed object documentation detected",
                "changed_paths": [],
                "changed_uuids": [],
                "counts": {"rules": 0, "objectives": 0, "threats": 0},
                "output": str(ctx.output_dir),
            }
        counts = run_objects(ctx, target_uuids=target_uuids)
        # Pages are removed by what the catalogue no longer writes, not by the
        # diff: a moved file shows up as a deletion, and a deleted object's name
        # can be the name a live object now has.
        removed = len(prune_stale_pages(ctx, catalog))
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
    scopes = OBJECT_SCOPES if resolved is None else (resolved,)
    removed = len(prune_stale_pages(ctx, build_catalog(), scopes))
    if resolved is None:
        run_index(ctx)
        return {
            "message": "Full documentation pipeline completed",
            "counts": counts,
            "removed": removed,
            "output": str(ctx.output_dir),
        }

    return {
        "message": f"Documentation scope {resolved.value} completed",
        "counts": counts,
        "removed": removed,
    }
