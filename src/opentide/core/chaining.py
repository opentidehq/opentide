"""Threat vector chaining graph utilities."""

from __future__ import annotations

from typing import Any


def compute_chains(tvm_index: dict[str, Any]) -> dict[str, dict[str, list[str]]]:
    """Build {tvm_uuid: {relation: [vector_uuid, ...]}} from threat objects."""
    chain: dict[str, dict[str, list[str]]] = {}
    for tvm, payload in tvm_index.items():
        if not isinstance(payload, dict):
            continue
        threat = payload.get("threat", {})
        if not isinstance(threat, dict):
            continue
        chaining = threat.get("chaining")
        if not chaining or not isinstance(chaining, list):
            continue
        chain.setdefault(tvm, {})
        for link in chaining:
            if not isinstance(link, dict):
                continue
            relation = link.get("relation")
            vector = link.get("vector")
            if not relation or not vector:
                continue
            chain[tvm].setdefault(str(relation), [])
            vector_id = str(vector)
            if vector_id not in chain[tvm][str(relation)]:
                chain[tvm][str(relation)].append(vector_id)
    return chain
