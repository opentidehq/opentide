"""The tenant examples in the bundled platform templates are usable as shipped.

``setup platforms`` writes each template with a commented ``[[tenants]]``
example, and the user enables a tenant by uncommenting it. Every template
used to ship a ``proxy = …`` line, a retired key that fails tenant parsing.
HarfangLab offered ``type = "YARA" or "Sigma"`` and SentinelOne a bare
``url =`` and ``account_id =``, neither of which is TOML.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

from opentide.ci.stages import platform_credential_names_for
from opentide.platforms.config import build_system_config

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

TEMPLATES = sorted(
    (Path(__file__).resolve().parents[2] / "src/opentide/data/configurations/platforms").glob(
        "*.toml"
    )
)
_RETIRED_PROXY = re.compile(r"^#?\s*proxy\s*=", re.MULTILINE)
_EXAMPLE_START = re.compile(r"^# ?\[\[tenants\]\]\s*$")
_COMMENT = re.compile(r"^# ?")


def uncomment_tenant_example(text: str) -> str:
    """Uncomment the ``[[tenants]]`` example block, up to the first blank line."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if _EXAMPLE_START.match(line))
    end = start
    while end < len(lines) and lines[end].strip():
        end += 1
    example = [_COMMENT.sub("", line, count=1) for line in lines[start:end]]
    return "\n".join([*lines[:start], *example, *lines[end:]]) + "\n"


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda path: path.stem)
def test_bundled_template_has_no_retired_proxy_key(template: Path) -> None:
    assert not _RETIRED_PROXY.search(template.read_text(encoding="utf-8"))


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda path: path.stem)
def test_uncommented_tenant_example_loads(template: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    system = template.stem
    for name in platform_credential_names_for(system):
        monkeypatch.setenv(name, "1")
    raw = tomllib.loads(uncomment_tenant_example(template.read_text(encoding="utf-8")))
    assert len(raw["tenants"]) == 1

    config = build_system_config(system, raw)

    assert config.tenants is not None
    assert len(config.tenants) == 1
    assert config.tenants[0].setup is not None


def test_every_platform_template_is_checked() -> None:
    assert len(TEMPLATES) == 7
