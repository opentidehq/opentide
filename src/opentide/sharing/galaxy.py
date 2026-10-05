"""Resolve threat-actor and mitre-attack-pattern tags from a read-only lookup.

The connector never creates or edits galaxies. A failed lookup is
``galaxy_lookup_failed`` and leaves the remote Event untouched.
"""

from __future__ import annotations

from dataclasses import dataclass

from opentide.sharing.client import (
    GALAXY_ACTOR,
    GALAXY_ATTACK,
    GalaxyCluster,
    MispCallError,
    MispClient,
)

_ACTOR_SCOPES = frozenset({"att&ck", "misp"})


@dataclass(frozen=True)
class GalaxyResolution:
    """Tags to emit, and informational notes. ``error`` stops the object."""

    tags: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    error: MispCallError | None = None


def resolve_clusters(client: MispClient, sources: tuple[str, ...]) -> GalaxyResolution:
    """Map technique and actor identifiers to cluster tags."""
    if not sources:
        return GalaxyResolution()
    attack: tuple[GalaxyCluster, ...] | None = None
    actors: tuple[GalaxyCluster, ...] | None = None
    actor_tags: list[str] = []
    attack_tags: list[str] = []
    notes: list[str] = []
    try:
        for source in sources:
            kind, _, ident = source.partition(":")
            if kind == "technique":
                if attack is None:
                    attack = client.galaxy_clusters(GALAXY_ATTACK)
                tag, note = _technique(attack, ident)
                bucket = attack_tags
            else:
                if actors is None:
                    actors = client.galaxy_clusters(GALAXY_ACTOR)
                tag, note = _actor(actors, ident)
                bucket = actor_tags
            if note:
                notes.append(note)
            if tag and tag not in bucket:
                bucket.append(tag)
    except MispCallError as exc:
        return GalaxyResolution(
            error=MispCallError(exc.kind, "galaxy_lookup_failed", status=exc.status)
        )
    actor_tags.sort()
    attack_tags.sort()
    return GalaxyResolution(tags=tuple(actor_tags + attack_tags), notes=tuple(notes))


def _technique(
    clusters: tuple[GalaxyCluster, ...], technique: str
) -> tuple[str | None, str | None]:
    matched = [
        cluster
        for cluster in clusters
        if any(_same(item, technique) for item in cluster.external_ids)
    ]
    return _one(matched, f"cluster_not_found:{technique}", GALAXY_ATTACK)


def _actor(clusters: tuple[GalaxyCluster, ...], name: str) -> tuple[str | None, str | None]:
    scope, separator, ident = name.partition("::")
    if separator == "" or scope not in _ACTOR_SCOPES or not ident:
        return None, f"actor_unscoped:{name}"
    if scope == "misp":
        matched = [cluster for cluster in clusters if cluster.uuid.casefold() == ident.casefold()]
        return _one(matched, f"cluster_not_found:{name}", GALAXY_ACTOR)
    predicates = (
        lambda cluster: any(_same(item, ident) for item in cluster.external_ids),
        lambda cluster: any(tail == ident for tail in cluster.ref_tails),
        lambda cluster: any(_same(item, ident) for item in cluster.synonyms),
    )
    for predicate in predicates:
        matched = [cluster for cluster in clusters if predicate(cluster)]
        if len(matched) == 1:
            return _tag(GALAXY_ACTOR, matched[0].value), None
        if len(matched) > 1:
            uuids = ",".join(sorted(cluster.uuid for cluster in matched))
            return None, f"cluster_ambiguous:{uuids}"
    return None, f"cluster_not_found:{name}"


def _one(
    matched: list[GalaxyCluster],
    missing: str,
    galaxy: str,
) -> tuple[str | None, str | None]:
    if len(matched) == 1:
        return _tag(galaxy, matched[0].value), None
    if len(matched) > 1:
        uuids = ",".join(sorted(cluster.uuid for cluster in matched))
        return None, f"cluster_ambiguous:{uuids}"
    return None, missing


def _tag(galaxy: str, value: str) -> str:
    return f'misp-galaxy:{galaxy}="{value}"'


def _same(left: str, right: str) -> bool:
    return left.strip().casefold() == right.strip().casefold()
