"""CoreTIDE content is not a supported input, so nothing in the package may act as if it were.

Migrating CoreTIDE content to opentide is not a supported path. The pieces that
suggested otherwise (a ``migrate objects`` command, a migration guide, the
``global.toml`` layout, the ``[tide]`` platform table, splunk::2.x keys, an
objective's root ``composition``) accepted CoreTIDE files half-way, read them and
ignored them, or kept CoreTIDE names alive, and a real migration stumbled on each.
These checks keep them from coming back: by name in the package and the user
documentation, and by behaviour in the models and the configuration loader.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "src" / "opentide"
DOCS = ROOT / "docs"

#: Names and paths of the CoreTIDE layout, its schemas and its templates.
_CORETIDE_MARKERS = re.compile(
    r"(?i:core\s?tide)|Objects/(?:Detection Rules|Detection Objectives|Threat Vectors)"
    r"|Models Library|MDR Systems Deployment|Sub Schema|Schemas/Templates"
    r"|Configurations/systems|\bmdr::\d|TVM TEMPLATE|MDR TEMPLATE|MDR Schema\.json"
    r"|TVM Schema\.json|ATT&CK Navigator Layer\.json|Objects Table\.csv"
)

#: History, not guidance: release notes keep what each release did.
_HISTORY = {DOCS / "usage" / "releases.md"}
#: Maintainer records of how this repository was built.
_INTERNAL = DOCS / "internal"
#: Synced verbatim from opentidehq/specifications (`scripts/build/sync_vocabularies.py`).
_UPSTREAM = PACKAGE / "data" / "vocabulary"

_TEXT_SUFFIXES = {".py", ".pyi", ".toml", ".md", ".mdx", ".yaml", ".yml", ".json", ".txt"}


def _text_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix in _TEXT_SUFFIXES
        and "__pycache__" not in path.parts
        and path not in _HISTORY
        and _INTERNAL not in path.parents
        and _UPSTREAM not in path.parents
    )


@pytest.mark.parametrize("root", [PACKAGE, DOCS], ids=["package", "docs"])
def test_no_coretide_name_or_layout_is_left(root: Path) -> None:
    found = [
        f"{path.relative_to(ROOT)}:{number}: {match.group(0)}"
        for path in _text_files(root)
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if (match := _CORETIDE_MARKERS.search(line))
    ]
    assert not found, "\n".join(found)


def test_no_retired_file_is_bundled() -> None:
    configurations = PACKAGE / "data" / "configurations"
    for name in ("global.toml", "schema.toml", "systems"):
        assert not (configurations / name).exists(), name
    assert not (
        PACKAGE / "schemas" / "data" / "platform_templates" / "MDR Systems Deployment"
    ).exists()


def test_no_bundled_platform_file_carries_a_retired_key() -> None:
    for path in sorted((PACKAGE / "data" / "configurations" / "platforms").glob("*.toml")):
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        assert "tide" not in document, path.name
        assert set(document.get("platform", {})) <= {"enabled", "name", "description"}, path.name


def test_the_migrate_group_has_no_layout_command() -> None:
    from opentide.cli.commands.migrate import migrate_app

    assert [command.name for command in migrate_app.registered_commands] == ["vocab-scope"]


def test_no_model_accepts_a_key_it_does_not_define() -> None:
    """A model that rewrote or dropped a legacy key is how CoreTIDE files loaded half-way.

    Elastic and Sysdig normalise their own opentide spellings (an empty map each);
    nothing else may declare legacy keys.
    """
    from opentide._models.objective import DetectionObjective
    from opentide._models.platform import PLATFORM_CONFIG_MODELS
    from opentide._models.rule import DetectionRule
    from opentide._models.threat import ThreatVector

    for model in (
        DetectionRule,
        DetectionObjective,
        ThreatVector,
        *PLATFORM_CONFIG_MODELS.values(),
    ):
        assert not model.__legacy_keys__, model.__name__
        assert model.model_config.get("extra") == "forbid", model.__name__


def test_configuration_models_have_no_retired_table() -> None:
    from opentide._models.configuration import CONFIGURATION_FILE_MODELS
    from opentide._models.configuration.deployment import DebugSettings
    from opentide._models.configuration.paths import PathsConfiguration, WorkspacePaths
    from opentide._models.configuration.platforms import (
        PLATFORM_CONFIGURATION_MODELS,
        PlatformIdentity,
    )

    assert set(CONFIGURATION_FILE_MODELS) == {
        "paths.toml",
        "deployment.toml",
        "visibility.toml",
        "documentation.toml",
        "sharing.toml",
    }
    assert set(PathsConfiguration.model_fields) == {"objects", "paths", "artifacts", "metaschemas"}
    assert set(WorkspacePaths.model_fields) == {"opentide", "objects", "exports", "docs"}
    assert set(PlatformIdentity.model_fields) == {"enabled", "name", "description"}
    assert "proxy_enabled" not in DebugSettings.model_fields
    for identifier, model in PLATFORM_CONFIGURATION_MODELS.items():
        legacy = {"tide", "setup", "secrets", "defaults", "validation"} & set(model.model_fields)
        assert not legacy, (identifier, legacy)
