"""OpenTide programmatic registry — explicit lifecycle and typed object access."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from opentide.core import index_manager as index_mod
from opentide.core import runtime
from opentide.core.environment import DebugHelpers  # noqa: F401
from opentide.loading.compat import ObjectLoader  # noqa: F401
from opentide.models.deployment_enums import DetectionPlatforms  # noqa: F401
from opentide.models.objective import DetectionObjective
from opentide.models.results import ValidationResult
from opentide.models.rule import DetectionRule
from opentide.models.threat import ThreatVector
from opentide.models.visibility import VisibilityConfig
from opentide.platforms.registry import PlatformsRegistry

IndexManager = index_mod.IndexManager

TideObject = DetectionRule | DetectionObjective | ThreatVector


class OpenTideRegistry:
    """Unified programmatic interface with explicit initialisation lifecycle."""

    def __init__(self) -> None:
        self._initialised = False
        self._objects_loaded = False
        self._index: dict[str, Any] | None = None
        self._rules: dict[str, DetectionRule] = {}
        self._threats: dict[str, ThreatVector] = {}
        self._objectives: dict[str, DetectionObjective] = {}
        self.Platforms = PlatformsRegistry()

    def initialise(self) -> None:
        """Load index into memory (typed objects load on first access)."""
        self._index = IndexManager.load()
        self._initialised = True

    def reload(self) -> None:
        """Refresh index and clear typed object caches."""
        IndexManager.reload()
        self._index = IndexManager.load()
        self._rules = {}
        self._threats = {}
        self._objectives = {}
        self._objects_loaded = False
        self._initialised = True

    def _require_init(self) -> None:
        if not self._initialised or self._index is None:
            self.initialise()

    def _ensure_objects_loaded(self) -> None:
        self._require_init()
        if not getattr(self, "_objects_loaded", False):
            self._load_objects()
            self._objects_loaded = True

    def _load_objects(self) -> None:
        assert self._index is not None
        objects = self._index["objects"]
        files = self._index.get("files", {})

        self._rules = {}
        for uuid, data in objects.get("rule", {}).items():
            file_path = _resolve_file("rule", files.get(uuid), self._index)
            from opentide.loading.rule_loader import load_rule_from_dict

            rule = load_rule_from_dict(data, file=file_path)
            self._rules[uuid] = rule.bind_registry(self)

        self._threats = {}
        for uuid, data in objects.get("threat", {}).items():
            self._threats[uuid] = ThreatVector.from_yaml_dict(data)

        self._objectives = {}
        from opentide.loading.objective_loader import load_objective_from_dict

        for uuid, data in objects.get("objective", {}).items():
            self._objectives[uuid] = load_objective_from_dict(data)

    @property
    def Rules(self) -> dict[str, DetectionRule]:
        self._ensure_objects_loaded()
        return self._rules

    @property
    def Threats(self) -> dict[str, ThreatVector]:
        self._ensure_objects_loaded()
        return self._threats

    @property
    def Objectives(self) -> dict[str, DetectionObjective]:
        self._ensure_objects_loaded()
        return self._objectives

    @property
    def Index(self) -> dict[str, Any]:
        self._require_init()
        assert self._index is not None
        return self._index

    @property
    def debug(self) -> bool:
        return runtime.is_debug()

    @property
    def ci(self) -> bool:
        return runtime.is_ci()

    @property
    def root(self) -> Path:
        return runtime.repo_root()

    def lookup(self, uuid: str) -> TideObject | None:
        """Cross-type UUID search across rules, threats, and objectives."""
        self._ensure_objects_loaded()
        if uuid in self._rules:
            return self._rules[uuid]
        if uuid in self._threats:
            return self._threats[uuid]
        if uuid in self._objectives:
            return self._objectives[uuid]
        return None

    def validate_rule(self, rule: DetectionRule) -> ValidationResult:
        from opentide.validation.pipeline import validate_object

        return validate_object(rule, "rule")

    def document_rule(self, rule: DetectionRule) -> str:
        from opentide.documentation.rule_export import document_detection_rule

        return document_detection_rule(rule)

    def promote_rule(self, rule: DetectionRule, target_status: str) -> None:
        raise NotImplementedError("promote_rule requires Orchestration/mutate integration")

    @property
    def Configuration(self) -> _ConfigurationAccessor:
        self._require_init()
        assert self._index is not None
        return _ConfigurationAccessor(self._index)

    @property
    def Configurations(self) -> _ConfigurationAccessor:
        return self.Configuration

    @property
    def Vocabularies(self) -> _VocabulariesAccessor:
        self._require_init()
        assert self._index is not None
        return _VocabulariesAccessor(self._index)

    @property
    def TideSchemas(self) -> _MetaSchemasAccessor:
        self._require_init()
        assert self._index is not None
        return _MetaSchemasAccessor(self._index)

    @property
    def MetaSchemas(self) -> _MetaSchemasAccessor:
        return self.TideSchemas

    @property
    def JsonSchemas(self) -> _SchemasAccessor:
        self._require_init()
        assert self._index is not None
        return _SchemasAccessor(self._index)

    @property
    def Schemas(self) -> _SchemasAccessor:
        return self.JsonSchemas

    @property
    def Templates(self) -> _TemplatesAccessor:
        self._require_init()
        assert self._index is not None
        return _TemplatesAccessor(self._index)

    @property
    def Models(self) -> _ModelsAccessor:
        self._require_init()
        assert self._index is not None
        return _ModelsAccessor(self._index, self._rules, self._objectives, self._threats)


OpenTide = OpenTideRegistry()


def _resolve_file(category: str, filename: str | None, index: dict[str, Any]) -> Path | None:
    if not filename:
        return None
    paths = index["paths"]
    base = paths.get(category)
    if base is None:
        return None
    return Path(base) / filename


@dataclass(frozen=True)
class _ConfigurationAccessor:
    _index: dict[str, Any]

    @property
    def Index(self) -> dict[str, Any]:
        return dict(self._index["configurations"])

    @property
    def Schema(self) -> dict[str, Any]:
        return dict(self._index["configurations"].get("schema", {}))

    @property
    def Sharing(self) -> dict[str, Any]:
        return dict(self._index["configurations"].get("sharing", {}))

    @property
    def Global(self) -> _GlobalConfig:
        return _GlobalConfig(self._index)

    @property
    def Systems(self) -> _SystemsConfig:
        return _SystemsConfig(self._index)

    @property
    def Documentation(self) -> _DocumentationConfig:
        return _DocumentationConfig(self._index)

    @property
    def Deployment(self) -> _DeploymentConfig:
        return _DeploymentConfig(self._index)

    @property
    def Visibility(self) -> _VisibilityConfig:
        return _VisibilityConfig(self._index)


@dataclass(frozen=True)
class _DocumentationConfig:
    _index: dict[str, Any]

    @property
    def Index(self) -> dict[str, Any]:
        return dict(self._index["configurations"].get("documentation", {}))

    @property
    def icons(self) -> dict[str, str]:
        return dict(self.Index.get("icons", {}))

    @property
    def object_names(self) -> dict[str, str]:
        return dict(self.Index.get("object_names", {}))


@dataclass(frozen=True)
class _DeploymentConfig:
    _index: dict[str, Any]

    @property
    def Index(self) -> dict[str, Any]:
        return dict(self._index["configurations"].get("deployment", {}))

    @property
    def statuses(self) -> list[Any]:
        import sys

        from opentide.core.root import repository_root

        root = str(repository_root())
        if root not in sys.path:
            sys.path.append(root)
        from opentide.loading.config_loader import ConfigurationsLoader

        return cast(list[Any], ConfigurationsLoader.load_statuses(self.Index["statuses"]))

    @property
    def debug(self) -> dict[str, Any]:
        return dict(self.Index.get("debug", {}))


@dataclass(frozen=True)
class _VisibilityConfig:
    _index: dict[str, Any]

    @property
    def Index(self) -> dict[str, Any]:
        return dict(self._index["configurations"].get("visibility", {}))

    def _load(self) -> VisibilityConfig | None:
        from opentide.loading.config_loader import ConfigurationsLoader

        return ConfigurationsLoader.load_visibility(self.Index)

    @property
    def visibility(self) -> VisibilityConfig | None:
        return self._load()

    @property
    def assets(self) -> list[Any] | None:
        loaded = self._load()
        return loaded.assets if loaded else None

    @property
    def logsources(self) -> list[Any] | None:
        loaded = self._load()
        return loaded.logsources if loaded else None

    @property
    def detectors(self) -> list[Any] | None:
        loaded = self._load()
        return loaded.detectors if loaded else None


@dataclass(frozen=True)
class _GlobalConfig:
    _index: dict[str, Any]

    @property
    def Index(self) -> dict[str, Any]:
        return dict(self._index["configurations"]["global"])

    @property
    def Paths(self) -> _PathsAccessor:
        return _PathsAccessor(self._index)

    @property
    def metaschemas(self) -> dict[str, str]:
        return dict(self.Index["metaschemas"])

    @property
    def templates(self) -> dict[str, str]:
        return dict(self.Index["templates"])

    @property
    def objects(self) -> list[str]:
        return list(self.Index.get("objects", []))

    @property
    def indexes(self) -> Any:
        return _paths_namespace(dict(self.Index.get("indexes", {})))

    @property
    def recomposition(self) -> dict[str, str]:
        return dict(self.Index.get("recomposition", {}))

    @property
    def json_schemas(self) -> dict[str, str]:
        return dict(self.Index.get("json_schemas", {}))

    @property
    def config_metaschemas(self) -> dict[str, str]:
        return dict(self.Index.get("config_metaschemas", {}))

    @property
    def config_json_schemas(self) -> dict[str, str]:
        return dict(self.Index.get("config_json_schemas", {}))

    @property
    def exports(self) -> Any:
        return _paths_namespace(dict(self.Index.get("exports", {})))

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        value = self.Index.get(name)
        if isinstance(value, dict):
            return _paths_namespace(value)
        if value is not None:
            return value
        raise AttributeError(name)


def _paths_namespace(paths: dict[str, Any]) -> Any:
    from types import SimpleNamespace

    return SimpleNamespace(**paths)


@dataclass(frozen=True)
class _PathsAccessor:
    _index: dict[str, Any]

    @property
    def Index(self) -> dict[str, Any]:
        return dict(IndexManager.return_paths(tier="all"))

    @property
    def Tide(self) -> Any:
        return _paths_namespace(IndexManager.return_paths(tier="tide"))

    @property
    def Core(self) -> Any:
        return _paths_namespace(IndexManager.return_paths(tier="core"))


@dataclass(frozen=True)
class _VocabulariesAccessor:
    _index: dict[str, Any]

    @property
    def Index(self) -> dict[str, Any]:
        import sys

        from opentide.core.root import repository_root

        root = str(repository_root())
        if root not in sys.path:
            sys.path.append(root)
        from opentide.generation.vocabulary import VocabularyLoader

        return cast(dict[str, Any], VocabularyLoader.load_index(self._index.get("vocabs")))


@dataclass(frozen=True)
class _MetaSchemasAccessor:
    _index: dict[str, Any]

    @property
    def Index(self) -> dict[str, Any]:
        return dict(self._index["metaschemas"])

    @property
    def subschemas(self) -> dict[str, Any]:
        return dict(self._index["subschemas"])

    @property
    def definitions(self) -> dict[str, Any]:
        return dict(self._index["definitions"])

    @property
    def templates(self) -> dict[str, Any]:
        return dict(self._index["templates"])


@dataclass(frozen=True)
class _SchemasAccessor:
    _index: dict[str, Any]

    @property
    def Index(self) -> dict[str, Any]:
        return dict(self._index["json_schemas"])


@dataclass(frozen=True)
class _TemplatesAccessor:
    _index: dict[str, Any]

    @property
    def Index(self) -> dict[str, Any]:
        return dict(self._index["templates"])


@dataclass(frozen=True)
class _ModelsAccessor:
    _index: dict[str, Any]
    _rules: dict[str, DetectionRule]
    _objectives: dict[str, DetectionObjective]
    _threats: dict[str, ThreatVector]

    @property
    def Index(self) -> dict[str, Any]:
        return dict(self._index["objects"])

    @property
    def rules(self) -> dict[str, Any]:
        return cast(dict[str, Any], self.Index.get("rule", {}))

    @property
    def objectives(self) -> dict[str, Any]:
        return cast(dict[str, Any], self.Index.get("objective", {}))

    @property
    def threats(self) -> dict[str, Any]:
        return cast(dict[str, Any], self.Index.get("threat", {}))

    @property
    def signals(self) -> dict[str, Any]:
        return cast(dict[str, Any], self.Index.get("signal", {}))

    @property
    def files(self) -> dict[str, Any]:
        return dict(self._index.get("files", {}))

    @property
    def chaining(self) -> dict[str, Any]:
        return IndexManager.compute_chains(self.threats)

    @property
    def FlatIndex(self) -> dict[str, Any]:
        return {**self.threats, **self.objectives, **self.signals, **self.rules}

    @property
    def Rules(self) -> dict[str, DetectionRule]:
        return self._typed_rules()

    @property
    def MDR(self) -> dict[str, DetectionRule]:
        return self.Rules

    @property
    def DOM(self) -> dict[str, DetectionObjective] | None:
        return self._objectives or None

    @property
    def Signals(self) -> dict[str, Any]:
        return self.signals

    def _typed_rules(self) -> dict[str, DetectionRule]:
        """Typed rule access for deployers."""
        from opentide.loading.rule_loader import load_rule_from_dict

        if self._rules:
            return dict(self._rules)

        files = self._index.get("files", {})
        typed: dict[str, DetectionRule] = {}
        for uuid, data in self.rules.items():
            file_path = _resolve_file("rule", files.get(uuid), self._index)
            typed[uuid] = load_rule_from_dict(data, file=file_path)
        return typed


@dataclass(frozen=True)
class _SystemsConfig:
    _index: dict[str, Any]

    @property
    def Index(self) -> dict[str, Any]:
        return dict(self._index["configurations"]["systems"])

    def __getattr__(self, name: str) -> Any:
        from opentide.platforms.config import build_system_config

        key = _snake_case(name)
        if key in self.Index:
            return build_system_config(key)
        raise AttributeError(name)


def _snake_case(class_name: str) -> str:
    parts: list[str] = []
    current = ""
    for char in class_name:
        if char.isupper() and current:
            parts.append(current.lower())
            current = char
        else:
            current += char
    if current:
        parts.append(current.lower())
    return "_".join(parts)
