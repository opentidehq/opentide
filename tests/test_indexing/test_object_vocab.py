"""Object vocabulary index building."""

from __future__ import annotations

from opentide.indexing.object_vocab import build_object_vocabularies


def test_build_object_vocabularies_mdr() -> None:
    objects = {
        "rule": {
            "uuid-1": {
                "name": "Rule A",
                "metadata": {"tlp": "clear"},
                "description": "Detects X",
            }
        }
    }
    vocab = build_object_vocabularies(
        object_scope=["rule"],
        models_index=objects,
        icons={"rule": "icon"},
        object_names={"rule": "Detection Rules"},
    )
    assert "rule" in vocab
    assert "uuid-1" in vocab["rule"]["entries"]
    assert vocab["rule"]["entries"]["uuid-1"]["name"] == "Rule A"
