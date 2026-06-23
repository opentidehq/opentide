"""Object vocabulary index building."""

from __future__ import annotations

from opentide.indexing.object_vocab import build_object_vocabularies


def test_build_object_vocabularies_mdr() -> None:
    objects = {
        "mdr": {
            "uuid-1": {
                "name": "Rule A",
                "metadata": {"tlp": "clear"},
                "description": "Detects X",
            }
        }
    }
    vocab = build_object_vocabularies(
        object_scope=["mdr"],
        models_index=objects,
        icons={"mdr": "icon"},
        object_names={"mdr": "Detection Rules"},
    )
    assert "mdr" in vocab
    assert "uuid-1" in vocab["mdr"]["entries"]
    assert vocab["mdr"]["entries"]["uuid-1"]["name"] == "Rule A"
