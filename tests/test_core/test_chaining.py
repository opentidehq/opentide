"""Tests for threat vector chaining utilities."""

from __future__ import annotations

from opentide.core.chaining import compute_chains


def test_compute_chains_builds_relation_map() -> None:
    payload = {
        "tvm-1": {
            "threat": {
                "chaining": [
                    {"relation": "enables", "vector": "vec-1"},
                    {"relation": "enables", "vector": "vec-1"},
                    {"relation": "targets", "vector": "vec-2"},
                ],
            },
        },
    }
    chains = compute_chains(payload)
    assert chains["tvm-1"]["enables"] == ["vec-1"]
    assert chains["tvm-1"]["targets"] == ["vec-2"]


def test_compute_chains_skips_non_mapping_payloads() -> None:
    assert compute_chains({"tvm-1": "not-a-dict"}) == {}


def test_compute_chains_skips_invalid_threat_and_links() -> None:
    payload = {
        "tvm-1": {
            "threat": "invalid",
        },
        "tvm-2": {
            "threat": {
                "chaining": [
                    "bad-link",
                    {"relation": "enables"},
                    {"relation": "enables", "vector": "vec-1"},
                ],
            },
        },
    }
    chains = compute_chains(payload)
    assert chains["tvm-2"]["enables"] == ["vec-1"]
