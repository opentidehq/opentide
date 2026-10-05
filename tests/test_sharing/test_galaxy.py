"""Galaxy lookup: equality, ambiguity, and the read-only failure."""

from __future__ import annotations

from opentide.sharing.client import GalaxyCluster, MispCallError
from opentide.sharing.galaxy import resolve_clusters


class _Clusters:
    def __init__(self, clusters: dict[str, tuple[GalaxyCluster, ...]]) -> None:
        self._clusters = clusters
        self.calls: list[str] = []

    def galaxy_clusters(self, galaxy: str) -> tuple[GalaxyCluster, ...]:
        self.calls.append(galaxy)
        return self._clusters.get(galaxy, ())


def test_empty_sources_skip_the_lookup() -> None:
    client = _Clusters({})
    assert resolve_clusters(client, ()).tags == ()  # type: ignore[arg-type]
    assert client.calls == []


def test_ambiguous_technique_and_actor_omit_the_tag() -> None:
    attack = (
        GalaxyCluster("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "One", ("T1059",), (), ()),
        GalaxyCluster("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "Two", (" T1059 ",), (), ()),
    )
    actors = (
        GalaxyCluster("cccccccc-cccc-4ccc-8ccc-cccccccccccc", "Alpha", ("G0007",), (), ()),
        GalaxyCluster("dddddddd-dddd-4ddd-8ddd-dddddddddddd", "Beta", ("g0007",), (), ()),
    )
    client = _Clusters({"mitre-attack-pattern": attack, "threat-actor": actors})
    resolved = resolve_clusters(
        client,  # type: ignore[arg-type]
        ("technique:T1059", "actor:att&ck::G0007"),
    )
    assert resolved.tags == ()
    assert any(note.startswith("cluster_ambiguous:") for note in resolved.notes)
    assert resolved.error is None


def test_actor_falls_through_external_id_to_refs_then_synonyms() -> None:
    by_ref = (
        GalaxyCluster(
            "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            "Ref",
            (),
            (),
            ("G0007",),
        ),
    )
    by_synonym = (
        GalaxyCluster(
            "ffffffff-ffff-4fff-8fff-ffffffffffff",
            "Syn",
            (),
            ("G0008",),
            (),
        ),
    )
    ref_client = _Clusters({"threat-actor": by_ref})
    ref = resolve_clusters(ref_client, ("actor:att&ck::G0007",))  # type: ignore[arg-type]
    assert ref.tags == ('misp-galaxy:threat-actor="Ref"',)
    synonym_client = _Clusters({"threat-actor": by_synonym})
    synonym = resolve_clusters(
        synonym_client,  # type: ignore[arg-type]
        ("actor:att&ck::G0008",),
    )
    assert synonym.tags == ('misp-galaxy:threat-actor="Syn"',)


def test_misp_actor_matches_the_cluster_uuid() -> None:
    cluster = GalaxyCluster(
        "5B4EE3EA-EEE3-4C8E-8323-85AE32658754",
        "Alpha",
        (),
        (),
        (),
    )
    client = _Clusters({"threat-actor": (cluster,)})
    resolved = resolve_clusters(
        client,  # type: ignore[arg-type]
        ("actor:misp::5b4ee3ea-eee3-4c8e-8323-85ae32658754",),
    )
    assert resolved.tags == ('misp-galaxy:threat-actor="Alpha"',)


def test_lookup_failure_is_galaxy_lookup_failed() -> None:
    class Down(_Clusters):
        def galaxy_clusters(self, galaxy: str) -> tuple[GalaxyCluster, ...]:
            raise MispCallError("connectivity", "connectivity_failed", status=503)

    resolved = resolve_clusters(Down({}), ("technique:T1059",))  # type: ignore[arg-type]
    assert resolved.error is not None
    assert resolved.error.reason == "galaxy_lookup_failed"
    assert resolved.error.status == 503
    assert resolved.tags == ()
