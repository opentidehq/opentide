"""Deploy's loaders refuse every key ``validate`` refuses, at every depth of a block.

``validate`` checks a platform block with ``<Platform>Config.model_validate``;
deploy, docs and the query checks build it with ``load_platform_config``. When a
loader kept only the keys it knew (Splunk's ``scheduling``), a misspelt or
retired key failed ``validate`` but was silently dropped by deploy, and the
splunk::2.x keys were rewritten by one path and not the other. Each corpus block
gets an unknown key at every mapping inside it, and both paths must refuse it.
"""

from __future__ import annotations

from collections.abc import Iterator
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from opentide._models.platform import PLATFORM_CONFIG_MODELS
from opentide.loading.platform_loader import load_platform_config

_RULES = (
    Path(__file__).resolve().parents[1] / "fixtures/tide_corpus/current/Objects/Detection Rules"
)
_UNKNOWN = "not_a_key_of_this_block"


def _blocks() -> Iterator[tuple[str, str, dict[str, Any]]]:
    for path in sorted(_RULES.glob("*.yaml")):
        body = yaml.safe_load(path.read_text(encoding="utf-8"))
        configurations = body.get("configurations") if isinstance(body, dict) else None
        if not isinstance(configurations, dict):
            continue
        for platform, block in configurations.items():
            if platform in PLATFORM_CONFIG_MODELS and isinstance(block, dict):
                yield path.name, platform, block


def _mapping_paths(node: Any, path: tuple[str | int, ...] = ()) -> Iterator[tuple]:
    if isinstance(node, dict):
        yield path
        for key, value in node.items():
            yield from _mapping_paths(value, (*path, key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _mapping_paths(value, (*path, index))


def _with_unknown_key(block: dict[str, Any], path: tuple) -> dict[str, Any]:
    copy = deepcopy(block)
    target: Any = copy
    for part in path:
        target = target[part]
    target[_UNKNOWN] = "x"
    return copy


_CASES = [
    pytest.param(platform, block, path, id=f"{name}:{platform}:{'.'.join(map(str, path)) or '.'}")
    for name, platform, block in _blocks()
    for path in _mapping_paths(block)
]


def test_the_corpus_has_a_block_for_every_platform() -> None:
    assert {platform for _, platform, _ in _blocks()} == set(PLATFORM_CONFIG_MODELS)


@pytest.mark.parametrize(("platform", "block", "path"), _CASES)
def test_an_unknown_key_fails_validate_and_deploy_alike(
    platform: str, block: dict[str, Any], path: tuple
) -> None:
    PLATFORM_CONFIG_MODELS[platform].model_validate(block)
    load_platform_config(platform, deepcopy(block))
    broken = _with_unknown_key(block, path)
    with pytest.raises(ValidationError):
        PLATFORM_CONFIG_MODELS[platform].model_validate(broken)
    with pytest.raises(ValidationError):
        load_platform_config(platform, broken)
