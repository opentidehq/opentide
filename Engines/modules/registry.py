import os
import git
import sys
from pathlib import Path
import json
from typing import (
    Any,
    Dict,
    Literal,
    Mapping,
    Never,
    Optional,
    Sequence,
    Tuple,
    Union,
    overload,
)
from functools import cache
from abc import ABC
from importlib import import_module
from copy import deepcopy

from dataclasses import dataclass, asdict

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.indexing.indexer import indexer
from Engines.modules.logs import log
from Engines.modules.models import (DetectionPlatforms,
                                    TideModels,
                                    SharedModels,
                                    ConfigurationModels,
                                    SystemConfig)
from Engines.modules.patching import Tide2Patching
from Engines.modules.datamodels.objects import Objects
from Engines.modules.datamodels.configurations import Configurations

ROOT = Path(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.environment import DebugHelpers
from Engines.modules.index import IndexManager
from Engines.modules.loaders.config_loader import ConfigurationsLoader
from Engines.modules.loaders.object_loader import ObjectLoader

class OpenTide:
    """Unified programmatic interface to access all data in the
    OpenTide instance. Calling this class triggers an indexation of the
    entire repository and stores it in memory.

    OpenTide execution model as a self-initializing dataclass means
    it will fetch all index data dynamically when the registry module is first
    imported in the execution environment, then freeze this state. To
    refresh OpenTide, call ``IndexManager.reload()``; a new OpenTide object
    will be initialized.
    """

    Index = IndexManager.load()

    _objects = dict(Index["objects"])
    _rules_raw = dict(_objects["mdr"])
    _threats_raw = dict(_objects["tvm"])
    _objectives_raw = dict(_objects.get("dom", {}))
    _signals_raw = dict(_objects.get("signal", {}))

    Rules = {
        uuid: ObjectLoader.load_rule(deepcopy(data))
        for uuid, data in dict(_rules_raw).items()
    }
    Threats = dict(_threats_raw)
    Objectives = (
        {
            uuid: ObjectLoader.load_objective(deepcopy(data))
            for uuid, data in dict(_objectives_raw).items()
        }
        if _objectives_raw
        else {}
    )

    @dataclass(frozen=True)
    class Models:
        """Legacy object collections — prefer OpenTide.Rules / .Threats / .Objectives."""

        _model_index = dict(IndexManager.load()["objects"])
        Index = dict(_model_index)
        tvm = dict(_model_index["tvm"])
        dom = dict(_model_index.get("dom", {}))
        DOM = (
            {
                uuid: ObjectLoader.load_objective(deepcopy(data))
                for uuid, data in dict(_model_index.get("dom", {})).items()
            }
            if dom
            else None
        )
        signal = dict(_model_index.get("signal", {}))
        Signal = (
            {
                uuid: ObjectLoader.load_signal(deepcopy(data))
                for uuid, data in dict(_model_index.get("signal", {})).items()
            }
            if signal
            else None
        )
        mdr = dict(_model_index["mdr"])
        MDR = {
            uuid: ObjectLoader.load_rule(deepcopy(data))
            for uuid, data in dict(_model_index["mdr"]).items()
        }
        chaining = IndexManager.compute_chains(tvm)
        FlatIndex = tvm | dom | signal | mdr
        files = dict(IndexManager.load()["files"])
    
    @dataclass(frozen=True)
    class Vocabularies:
        """TIDE Schema Interface.

        Exposes the vocabularies used across the instance
        """

        Index = dict(IndexManager.load()["vocabs"])

    class IndexCatalog:
        """
        Interface to compiled indexes
        """
        Index = dict(IndexManager.load()["indexes"])
        raw = dict(Index.get("objects", {}))
        revisions = dict(Index.get("revisions", {}))
        compiled = dict(Index.get("objects", {}))

    # Legacy alias
    Indexes = IndexCatalog

    @dataclass(frozen=True)
    class Schemas:
        """
        Interface to all the JSON Schemas generated from meta-schemas
        """

        Index = dict(IndexManager.load()["json_schemas"])
        threats = dict(Index.get("tvm", {}))
        objectives = dict(Index.get("dom", {}))
        rules = dict(Index.get("mdr", {}))
        # Legacy keys
        tvm = threats
        dom = objectives
        mdr = rules

    # Legacy alias
    JsonSchemas = Schemas

    @dataclass(frozen=True)
    class Templates:
        """
        Interface to all the templates generated from meta-schemas
        """

        Index = dict(IndexManager.load()["templates"])
        threats = str(Index.get("tvm"))
        objectives = str(Index.get("dom"))
        rules = str(Index.get("mdr"))
        dom = str(Index.get("dom"))
        tvm = threats
        mdr = rules

    @dataclass(frozen=True)
    class MetaSchemas:
        """OpenTide meta-schema interface."""

        Index = dict(IndexManager.load()["metaschemas"])
        subschemas = dict(IndexManager.load()["subschemas"])
        definitions = dict(IndexManager.load()["definitions"])
        templates = dict(IndexManager.load()["templates"])
        threats = dict(Index["tvm"])
        objectives = dict(Index.get("dom", {}))
        rules = dict(Index["mdr"])
        rules_v2 = dict(Index.get("mdrv2", {}))
        tvm = threats
        dom = objectives
        mdr = rules
        mdrv2 = rules_v2

    # Legacy alias
    TideSchemas = MetaSchemas

    @dataclass(frozen=True)
    class Configuration:
        Index = dict(IndexManager.load()["configurations"])
        DEBUG = DebugHelpers.is_debug()
        """Discovers whether the current execution context is considered
        to be a debugging one"""
        
        @dataclass(frozen=True)
        class Global:
            
            @dataclass
            class Indexes:
                objects: str
                revisions: str

            @dataclass
            class Exports:
                attack_layer: str
                table: str

            Index = dict(IndexManager.load()["configurations"]["global"])
            objects = Index["objects"]
            indexes = Indexes(**dict(Index["indexes"]))
            exports = Exports(**dict(Index["exports"]))
            metaschemas = dict(Index["metaschemas"])
            recomposition = dict(Index["recomposition"])
            json_schemas = dict(Index["json_schemas"])
            config_metaschemas = dict(Index.get("config_metaschemas", {}))
            config_json_schemas = dict(Index.get("config_json_schemas", {}))
            data_fields = dict(Index["data_fields"])
            templates = dict(Index["templates"])

            @dataclass(frozen=True)
            class Paths:
                Index = IndexManager.return_paths(tier="all")
                _raw = dict(IndexManager.load()["paths"]["raw"])
                """Paths without the proper absolute calculation.
                Only use for specific use cases, for any others prefer
                the other attributes which are precomputed"""

                @dataclass(frozen=True)
                class Core:
                    """Paths to Tide Internals"""

                    _path_index = IndexManager.return_paths(tier="core")
                    Index = _path_index
                    _raw = dict(IndexManager.load()["paths"]["raw"]["core"])
                    """Paths without the proper absolute calculation.
                    Only use for specific use cases, for any others prefer
                    the other attributes which are precomputed"""
                    vocabularies = _path_index["vocabularies"]
                    configurations = _path_index["configurations"]
                    metaschemas = _path_index["configurations"]
                    subschemas = _path_index["subschemas"]
                    definitions = _path_index["definitions"]
                    wiki_docs_folder = _path_index["wiki_docs_folder"]
                    models_docs_folder = _path_index["models_docs_folder"]
                    schemas_docs_folder = _path_index["schemas_docs_folder"]
                    vocabularies_docs = _path_index["vocabularies_docs"]
                    resources = _path_index["resources"]

                @dataclass(frozen=True)
                class Tide:
                    """Paths to Tide Content, Models, and Artifacts at
                    the top level directory"""

                    _path_index = IndexManager.return_paths(tier="tide")
                    Index = _path_index
                    _raw = dict(IndexManager.load()["paths"]["raw"]["tide"])
                    """Paths without the proper absolute calculation.
                    Only use for specific use cases, for any others prefer
                    the other attributes which are precomputed"""
                    
                    tvm = _path_index["tvm"]
                    dom = _path_index.get("dom")
                    mdr = _path_index["mdr"]
                    analytics = _path_index["analytics"]
                    snippet_file = _path_index["snippet_file"]
                    json_schemas = _path_index["json_schemas"]
                    templates = _path_index["templates"]
                    tide_indexes = _path_index["tide_indexes"]
                    exports = _path_index["exports"]

        @dataclass(frozen=True)
        class Systems:
            Index = dict(IndexManager.load()["configurations"]["systems"])

            @dataclass(frozen=True)
            class Splunk:
                Index = dict(IndexManager.load()["configurations"]["systems"]["splunk"])
                tide = dict(Index["tide"])
                setup = dict(Index["setup"])
                secrets = dict(Index["secrets"])
                defaults = dict(Index["defaults"])
                modifiers = dict(Index.get("modifiers", {}))

            @dataclass(frozen=True)
            class CarbonBlackCloud:
                Index = dict(
                    IndexManager.load()["configurations"]["systems"]["carbon_black_cloud"]
                )
                tide = dict(Index["tide"])
                setup = dict(Index["setup"])
                secrets = dict(Index["secrets"])
                validation = dict(Index["validation"])

            @dataclass
            class Sentinel(ConfigurationModels.Systems.Sentinel):
                raw = dict(
                    IndexManager.load()["configurations"]["systems"]["sentinel"]
                )
                platform = ObjectLoader.load_platform_config(dict(raw["platform"]), DetectionPlatforms.SENTINEL)
                modifiers = ObjectLoader.load_modifiers_config(raw["modifiers"]) if raw.get("modifiers") else None
                tenants = ObjectLoader.load_tenants_config(raw["tenants"], DetectionPlatforms.SENTINEL) if raw.get("tenants") else None

            @dataclass
            class DefenderForEndpoint(ConfigurationModels.Systems.DefenderForEndpoint):
                raw = dict(
                    IndexManager.load()["configurations"]["systems"]["defender_for_endpoint"]
                )
                platform = ObjectLoader.load_platform_config(dict(raw["platform"]), DetectionPlatforms.DEFENDER_FOR_ENDPOINT)
                modifiers = ObjectLoader.load_modifiers_config(raw["modifiers"]) if raw.get("modifiers") else None
                tenants = ObjectLoader.load_tenants_config(raw["tenants"], DetectionPlatforms.DEFENDER_FOR_ENDPOINT) if raw.get("tenants") else None

            @dataclass
            class SentinelOne(ConfigurationModels.Systems.SentinelOne):
                raw = dict(
                    IndexManager.load()["configurations"]["systems"]["sentinel_one"]
                )
                platform = ObjectLoader.load_platform_config(dict(raw["platform"]), DetectionPlatforms.SENTINEL_ONE)
                modifiers = ObjectLoader.load_modifiers_config(raw["modifiers"]) if raw.get("modifiers") else None
                tenants = ObjectLoader.load_tenants_config(raw["tenants"], DetectionPlatforms.SENTINEL_ONE) if raw.get("tenants") else None

            @dataclass
            class Crowdstrike(ConfigurationModels.Systems.Crowdstrike):
                raw = dict(
                    IndexManager.load()["configurations"]["systems"]["crowdstrike"]
                )
                platform = ObjectLoader.load_platform_config(dict(raw["platform"]), DetectionPlatforms.CROWDSTRIKE)
                modifiers = ObjectLoader.load_modifiers_config(raw["modifiers"]) if raw.get("modifiers") else None
                tenants = ObjectLoader.load_tenants_config(raw["tenants"], DetectionPlatforms.CROWDSTRIKE) if raw.get("tenants") else None

            @dataclass
            class HarfangLab(ConfigurationModels.Systems.HarfangLab):
                raw = dict(
                    IndexManager.load()["configurations"]["systems"]["harfanglab"]
                )
                platform = ObjectLoader.load_platform_config(dict(raw["platform"]), DetectionPlatforms.HARFANGLAB)
                modifiers = ObjectLoader.load_modifiers_config(raw["modifiers"]) if raw.get("modifiers") else None
                tenants = ObjectLoader.load_tenants_config(raw["tenants"], DetectionPlatforms.HARFANGLAB) if raw.get("tenants") else None

        @dataclass(frozen=True)
        class Documentation:
            """Parameters describing how documentation should be generated."""


            Index = dict(IndexManager.load()["configurations"]["documentation"])
            scope = list(Index["scope"])
            skip_model_keys = list(Index["skip_model_keys"])
            skip_vocabularies = list(Index["skip_model_keys"])
            gitlab = dict(Index.get("gitlab", {}))
            model_cover_pages:bool = Index.get("model_cover_pages", False)
            cve = dict(Index["cve"])
            wiki = dict(Index.get("wiki",{}))
            object_names = dict(Index["object_names"])
            titles = dict(Index["titles"])
            icons = dict(Index["icons"])
            models_docs_folder:Path = Path(
                IndexManager.load()["configurations"]["global"]["paths"]["core"][
                    "models_docs_folder"
                ]
            )

        @dataclass(frozen=True)
        class Resources:
            """Parameters pointing to External resources used by engines."""
            Index = dict(IndexManager.load()["configurations"]["resources"])
            attack = dict(Index["attack"])
            d3fend = dict(Index["d3fend"])
            engage = dict(Index["engage"])
            nist = dict(Index["nist"])
            misp = dict(Index["misp"])

        @dataclass(frozen=True)
        class Deployment:
            """Generic deployment parameters."""

            Index = dict(IndexManager.load()["configurations"]["deployment"])
            statuses = ConfigurationsLoader.load_statuses(Index["statuses"])
            promotion = dict(Index["promotion"])
            default_responders = str(Index["default_responders"])
            proxy = dict(Index["proxy"])
            debug = dict(Index["debug"])

        @dataclass(frozen=True)
        class Visibility:
            """OpenTide instance visibility configuration including logsources, assets, and detectors"""
            Index = dict(IndexManager.load()["configurations"]["visibility"])
            visibility = ConfigurationsLoader.load_visibility(Index)
            assets = visibility.assets if visibility else None
            detectors = visibility.detectors if visibility else None
            logsources = visibility.logsources if visibility else None

        @dataclass(frozen=True)
        class Schema:
            Index = dict(IndexManager.load()["configurations"].get("schema", {}))

        @dataclass(frozen=True)
        class Sharing:
            Index = dict(IndexManager.load()["configurations"].get("sharing", {}))

        Index = dict(IndexManager.load()["configurations"])

    # Legacy alias
    Configurations = Configuration

    @staticmethod
    def initialise() -> None:
        """Explicit initialisation hook (index loads at import time)."""
        IndexManager.load()


# Legacy alias
DataTide = OpenTide
