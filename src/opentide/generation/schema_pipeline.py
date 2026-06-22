from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, cast

import git
import yaml

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.deployment import enabled_systems
from Engines.modules.documentation import get_icon
from Engines.modules.files import resolve_paths
from Engines.modules.framework import get_type, get_vocab_entry
from Engines.modules.logs import log
from Engines.modules.models import StatusStrategy
from Engines.modules.tide import OpenTide
from Engines.modules.vocabulary import VocabularyDefinition, entry_key_field

GLOBAL_CONFIG = OpenTide.Configurations.Global

VOCAB_INDEX = OpenTide.Vocabularies.Index
CONFIG_INDEX = OpenTide.Configurations.Index
PATHS = resolve_paths()

# Vocabulary Extensions — user-defined entries injected at schema compilation
# Loaded from [vocabulary] section in schema.toml
SCHEMA_CONFIG = CONFIG_INDEX.get("schema", {})
VOCAB_EXTENSIONS = SCHEMA_CONFIG.get("vocabulary", {})

# Configuration settings fetching routine
METASCHEMAS_FOLDER = Path(PATHS["metaschemas"])
VOCABS_FOLDER = Path(PATHS["vocabularies"])
JSON_SCHEMA_FOLDER = Path(PATHS["json_schemas"])
ICONS = OpenTide.Configurations.Documentation.icons
OBJECT_TYPES = OpenTide.Configurations.Global.objects
SUBSCHEMAS_PATH = Path(PATHS["subschemas"])
RECOMPOSITION = GLOBAL_CONFIG.recomposition


class VocabularyResolver:
    """Resolves all dynamic enum values for JSON Schema generation.

    Nested classes handle each data source — vocabularies, visibility
    configuration, deployment statuses, etc. — while shared formatting
    utilities live on the outer class.

    Usage::

        VocabularyResolver.Vocabulary("surface", stages="os").resolve()
        VocabularyResolver.Logsources().resolve()
        VocabularyResolver.Detectors().resolve()
        VocabularyResolver.Statuses().resolve()
        VocabularyResolver.Parameters("systems.splunk.indexes").resolve()
        VocabularyResolver.SystemTenants("splunk").resolve()
    """

    # ------------------------------------------------------------------
    # Shared visibility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _visibility():
        """Return the visibility configuration, or ``None``."""
        return OpenTide.Configurations.Visibility.visibility

    @staticmethod
    def _asset_map(visibility_data):
        """Build ``{name: asset}`` lookup from visibility assets."""
        if visibility_data and visibility_data.assets:
            return {a.name: a for a in visibility_data.assets}
        return {}

    @staticmethod
    def _format_asset(asset_name: str, asset_map: dict) -> str:
        """Format a single asset entry as markdown."""
        asset = asset_map.get(asset_name)
        if not asset:
            return (
                f"\n- ⚠️ **{asset_name}**"
                f"\n  - _Warning_: Asset not found in configuration"
                f"\n  - _Action Required_: Define this asset in the assets section"
            )
        text = (
            f"\n- **{asset.name}**"
            f"\n  - _Criticality_: {asset.criticality}"
            f"\n  - _Description_: {asset.description}"
        )
        if asset.custom_details:
            text += "\n  - _Custom Details_:"
            for k, v in asset.custom_details.items():
                text += f"\n    - {k}: {v}"
        return text

    # ==================================================================
    # Vocabulary
    # ==================================================================

    class Vocabulary:
        """Resolve vocabulary entries into JSON Schema enum arrays.

        Reads entries from the core vocabulary index and any user-defined
        extensions (``[vocabulary]`` in ``schema.toml``), producing
        parallel lists of enum values and their markdown descriptions.

        Handles three patterns:

        * **Model vocabularies** (keyed by id) — all entries emitted with
          optional scope-prefixing and VS Code search hints.
        * **General, non-scoped** — entries filtered by stages, emitted
          with their name as the value.
        * **General, scoped** — entries expanded to ``stage::name`` per
          matching stage.
        """

        _STAGE_DESC_LIMIT = 300

        _DROPDOWN = """
### {icon} {name}

{id_icon} **Identifier** : `{identifier}`

_Vocabulary_ : `{source_vocab}`

{criticality} {tlp}

{stage}

{link}

---

{description}
"""

        _HINT_ABBREVS = (
            (" and ", " & "),
            (" without ", " w/o "),
            (" with ", " w/ "),
            (" to ", " "),
            (" of ", " "),
            (" a ", " "),
            (" an ", " "),
            ("Use", " "),
            ("used", " "),
            ("Using", " "),
        )

        def __init__(
            self,
            vocab: str,
            stages: str | list | None = None,
            no_wrap: bool = False,
            scoped: bool = False,
        ):
            self.vocab = vocab
            self.scoped = scoped
            self.no_wrap = no_wrap
            self.filter_stages: list | None = [stages] if isinstance(stages, str) else stages
            self.enum: list[str] = []
            self.enum_description: list[str] = []
            self._hints: list[str] = []
            self._hint_descriptions: list[str] = []
            self._hints_enabled = False

        # --- Public API -----------------------------------------------

        def resolve(self) -> tuple[list[str], list[str]]:
            """Resolve core + extension entries → ``(enum, descriptions)``."""
            log("DEBUG", "Resolving vocab enums for", self.vocab)
            self._ingest(VOCAB_INDEX.get(self.vocab))
            self._ingest_extensions()
            return self._finalise()

        # --- Ingestion ------------------------------------------------

        def _ingest(self, vocab_data: VocabularyDefinition | None):
            """Ingest entries from a vocabulary definition (core index)."""
            if not vocab_data:
                log("WARNING", "Could not retrieve vocabulary", self.vocab)
                return
            metadata = vocab_data.metadata
            self._hints_enabled = metadata.get("vocab.search_hints", True)
            is_model = metadata.model or (self.vocab in OBJECT_TYPES)
            entries = {key: entry.as_dict() for key, entry in vocab_data.entries.items()}
            self._process(entries, is_model=is_model)

        def _ingest_extensions(self):
            """Ingest user-defined extensions from ``schema.toml``."""
            extensions = VOCAB_EXTENSIONS.get(self.vocab, [])
            if not extensions:
                return
            log("DEBUG", f"Processing {len(extensions)} extension(s) for", self.vocab)
            ext_vocab = VOCAB_INDEX.get(self.vocab)
            ext_meta = ext_vocab.metadata if ext_vocab else None
            is_model = (ext_meta.model if ext_meta else False) or (self.vocab in OBJECT_TYPES)

            key_field = entry_key_field(model=is_model)
            normalised = {}
            for ext in extensions:
                d = ext.copy()
                key = d.pop(key_field, None)
                if not key:
                    log("WARNING", f"Extension missing '{key_field}'", self.vocab)
                    continue
                normalised[key] = d
            self._process(normalised, is_model=is_model)

        def _process(self, entries: dict, *, is_model: bool):
            """Iterate entries and emit enum values."""
            for key, data in entries.items():
                if is_model:
                    value = key
                    if self.scoped and data.get("tide.vocab.stages"):
                        raw_stages = data["tide.vocab.stages"]
                        stage = raw_stages[0] if isinstance(raw_stages, list) else raw_stages
                        value = stage + "::" + key
                    if self._emit(value, key, data) and self._hints_enabled:
                        self._hints.append(self._search_hint(value, data))
                        self._hint_descriptions.append(self.enum_description[-1])
                else:
                    raw = data.get("tide.vocab.stages", [])
                    stages = [raw] if not isinstance(raw, list) else raw
                    matching = (
                        [s for s in stages if s in self.filter_stages]
                        if self.filter_stages
                        else stages
                    )
                    if not self.scoped:
                        if not self.filter_stages or matching:
                            self._emit(key, key, data)
                    elif matching:
                        for stage in matching:
                            self._emit(
                                stage + "::" + key,
                                key,
                                {**data, "tide.vocab.stages": stage},
                            )

        def _emit(self, value: str, entry_key: str, data: dict) -> bool:
            """Append *value* if not already present (de-duplicate)."""
            if value in self.enum:
                log("INFO", f"Skipping duplicate in vocab {self.vocab}", value)
                return False
            self.enum.append(value)
            self.enum_description.append(self._dropdown(entry_key, data))
            return True

        def _finalise(self) -> tuple[list[str], list[str]]:
            if not self.enum:
                self.enum = [""]
            if self._hints and self._hints_enabled:
                self.enum.extend(self._hints)
                self.enum_description.extend(self._hint_descriptions)
            return self.enum, self.enum_description

        # --- Formatting -----------------------------------------------

        def _search_hint(self, value: str, data: dict) -> str:
            tips = data.get("name") or ""
            if data.get("alias"):
                tips += ", " + ", ".join(data["alias"])
            hint = value + " #" + tips.strip()
            if not self.no_wrap and len(hint) > 60:
                for old, new in self._HINT_ABBREVS:
                    hint = hint.replace(old, new)
            return hint

        def _dropdown(self, name: str, key: dict) -> str:
            identifier = key.get("id") or name
            display = key.get("name") or name
            if display.islower():
                display = display.title()

            icon = (
                key.get("icon")
                or (vocab_def.metadata.icon if (vocab_def := VOCAB_INDEX.get(self.vocab)) else "")
                or ICONS.get(self.vocab)
                or ""
            )
            source_vocab = (
                vocab_def.metadata.name if (vocab_def := VOCAB_INDEX.get(self.vocab)) else None
            )
            link = key.get("link") or ""
            stage = key.get("tide.vocab.stages") or ""
            tlp = key.get("tlp") or ""
            description = key.get("description") or ""

            criticality = ""
            if (get_type(identifier, mute=True) or "") in OBJECT_TYPES:
                crit = key.get("criticality")
                crit_icon = get_icon("criticality")
                if not crit:
                    criticality = f"{crit_icon} **Criticality** : No Criticality Assigned"
                else:
                    crit_value_icon = get_vocab_entry("criticality", crit, "icon")
                    criticality = f"{crit_icon} **Criticality** : {crit_value_icon} {crit}"

            if tlp:
                tlp = f" | **{get_icon(tlp, vocab='tlp')}TLP:{tlp.upper()}**"
            if stage:
                stage_text = self._stage_doc(stage)
                if stage_text:
                    stage = stage_text
                else:
                    stage = "`{}`".format(", ".join(stage) if isinstance(stage, list) else stage)

            return self._DROPDOWN.format(
                icon=icon,
                name=display,
                id_icon=ICONS["id"],
                identifier=identifier,
                source_vocab=source_vocab,
                criticality=criticality,
                tlp=tlp,
                stage=stage,
                link=link,
                description=description,
            )

        def _stage_doc(self, stages: str | list) -> str:
            vocab_def = VOCAB_INDEX.get(self.vocab)
            vocab_stages = vocab_def.metadata.get("stages") if vocab_def else None
            if not vocab_stages:
                log("WARNING", f"Could not find stages in vocabulary {self.vocab}")
                return ""
            if isinstance(stages, str):
                stages = [stages]
            parts: list[str] = []
            for stage in stages:
                for sd in vocab_stages:
                    if not isinstance(sd, dict):
                        continue
                    if (sd.get("id") or sd.get("name")) != stage:
                        continue
                    s_name = sd.get("name") or stage
                    s_icon = sd.get("icon") or ""
                    s_desc = sd["description"].strip()
                    limit = VocabularyResolver.Vocabulary._STAGE_DESC_LIMIT
                    if len(s_desc) > limit:
                        s_desc = s_desc[:limit] + "..."
                    parts.append(f"\n\n{s_icon} **{s_name}** : _{s_desc}_")
                    break
            return "".join(parts)

    # ==================================================================
    # Logsources
    # ==================================================================

    class Logsources:
        """Resolve log source entries from visibility configuration."""

        def resolve(self) -> None | tuple[list[str], list[str]]:
            visibility = VocabularyResolver._visibility()
            if not visibility or not visibility.logsources:
                return None
            asset_map = VocabularyResolver._asset_map(visibility)
            enums: list[str] = []
            descriptions: list[str] = []

            for ls in visibility.logsources:
                base = (
                    f"### {ls.name}\n**System**: {ls.system}\n**Description**: {ls.description}\n\n"
                )
                if ls.assets:
                    base += "### Associated Assets:\n"
                    for a in ls.assets:
                        base += VocabularyResolver._format_asset(a, asset_map) + "\n"

                if ls.tenants:
                    for tenant in ls.tenants:
                        enums.append(f"{ls.system}::{tenant}::{ls.name}")
                        descriptions.append(
                            base.replace(
                                "**System**:",
                                f"**System**: {ls.system}\n**Tenant**: {tenant}",
                            )
                        )
                else:
                    enums.append(f"{ls.system}::{ls.name}")
                    descriptions.append(base)

            return enums, descriptions

    # ==================================================================
    # Detectors
    # ==================================================================

    class Detectors:
        """Resolve external detector entries from visibility configuration."""

        def resolve(self) -> None | tuple[list[str], list[str]]:
            visibility = VocabularyResolver._visibility()
            if not visibility or not visibility.detectors:
                return None
            asset_map = VocabularyResolver._asset_map(visibility)
            enums: list[str] = []
            descriptions: list[str] = []

            for det in visibility.detectors:
                base = f"### {det.name}\n**Description**: {det.description}\n\n"
                if det.references:
                    base += "### References:\n"
                    for ref in det.references:
                        base += f"- {ref}\n"
                    base += "\n"
                if det.assets:
                    base += "### Monitored Assets:\n"
                    for a in det.assets:
                        base += VocabularyResolver._format_asset(a, asset_map) + "\n"

                enums.append(det.name)
                descriptions.append(base)

            return enums, descriptions

    # ==================================================================
    # Statuses
    # ==================================================================

    class Statuses:
        """Resolve deployment statuses from configuration."""

        def resolve(self) -> tuple[list[str], list[str]]:
            enums: list[str] = []
            descriptions: list[str] = []
            for status in OpenTide.Configurations.Deployment.statuses:
                enums.append(status.name)
                strategy = status.strategy.name  # type: ignore
                desc = (
                    f"**Strategy** : `{strategy}` "
                    f"- _{StatusStrategy[strategy].value}_"
                    f"\n\n{status.description}"
                )
                descriptions.append(desc)
            return enums, descriptions

    # ==================================================================
    # Parameters
    # ==================================================================

    class Parameters:
        """Resolve a configuration parameter list by dot-path."""

        def __init__(self, dot_path: str):
            self.dot_path = dot_path

        def resolve(self) -> list:
            config_index = OpenTide.Configurations.Index
            parts = self.dot_path.split(".")
            key = parts[0]
            while key != parts[-1]:
                if key == "tenants":
                    print(config_index)
                    param_key = parts[parts.index(key) + 1]
                    result: list[str] = []
                    for tenant in config_index["tenants"]:
                        name = tenant.get("name").strip()
                        if param_key in tenant.get("parameters", {}):
                            result.extend(
                                name + "::" + i.strip() for i in tenant["parameters"][param_key]
                            )
                    return result
                if key in config_index:
                    config_index = config_index[key]
                    key = parts[parts.index(key) + 1]
                else:
                    raise ValueError(f"Key : {key} could not be found in path {self.dot_path}")
            if type(config_index[key]) is list:
                return cast(list[Any], config_index[key])
            raise ValueError(
                f"Config path {self.dot_path} must be a valid path to a list parameter"
            )

    # ==================================================================
    # SystemTenants
    # ==================================================================

    class SystemTenants:
        """Resolve system tenant entries from configuration."""

        def __init__(self, system: str):
            self.system = system

        def resolve(self) -> tuple[list[str], list[str]]:
            config = OpenTide.Configurations.Index
            system_config = config.get("systems", {}).get(self.system)
            if not system_config:
                log(
                    "FATAL",
                    f"Could not retrieve configuration for system {self.system}",
                    f"Indexed Configurations : {str(config.keys())}",
                )
                raise ValueError(f"Missing configuration for system {self.system}")

            tenants: list[dict] = system_config.get("tenants")
            if not tenants:
                log(
                    "FATAL",
                    "Cannot retrieve a tenants section within the system configuration",
                    str(system_config),
                )
                raise ValueError(
                    f"System Configuration for {self.system} does not contain a tenants section"
                )

            enums: list[str] = []
            descriptions: list[str] = []
            for tc in tenants:
                name = tc.get("name")
                if not name:
                    log(
                        "FATAL",
                        "Cannot retrieve a tenant name in tenant definition",
                        str(tc),
                    )
                    raise ValueError("Missing name field in tenant definition")
                log("INFO", f"Discovered tenant definition {name}", tc.get("description", ""))
                enums.append(name)
                descriptions.append(tc.get("description", "No Description"))
            return enums, descriptions


def strip_framework_keywords(dictionary: dict) -> dict:
    """Backward-compatible wrapper — implementation in schema_utils."""
    from opentide.generation.schema_utils import strip_framework_keywords as _strip

    return _strip(dictionary)


def recomposition_handler(entry_point):

    recompositions = CONFIG_INDEX[entry_point]
    subschema_folder = OpenTide.Configurations.Global.recomposition[entry_point]
    recomposition = dict()
    # Generate a list of pivots
    for entry in recompositions:
        data = recompositions[entry]
        enabled = False

        if data.get("tide"):
            config_keyword = "tide"
        else:
            config_keyword = "platform"

        if data[config_keyword]["enabled"] == True:
            # recomp_entry = dict()
            recomp_identifier = entry
            recomposition[recomp_identifier] = dict()
            recomposition[recomp_identifier]["title"] = data[config_keyword]["name"]
            recomposition[recomp_identifier]["description"] = data[config_keyword]["description"]
            recomposition[recomp_identifier]["type"] = "object"

            recomp_source = data[config_keyword]["subschema"] + ".yaml"
            recomp_source_path = SUBSCHEMAS_PATH / subschema_folder / recomp_source
            recomp_data = yaml.safe_load(open(recomp_source_path, encoding="utf-8"))
            recomposition[recomp_identifier].update(recomp_data)

    return recomposition


def gen_json_schema(dictionary):
    """Recursively resolve OpenTide metaschema keywords into JSON Schema.

    Walks *dictionary* depth-first and replaces ``tide.*`` annotated
    fields with concrete JSON Schema constructs.  Vocabulary references
    (``tide.vocab``) are resolved via :meth:`VocabularyResolver.Vocabulary.resolve`;
    configuration-driven fields, recompositions and definitions are
    handled inline.

    Parameters
    ----------
    dictionary : dict
        A parsed metaschema (nested dict) to transform in-place.

    Returns
    -------
    dict
        The same *dictionary*, mutated with all ``tide.*`` keywords
        resolved into standard JSON Schema properties.
    """
    dict_foo = dictionary.copy()
    icon = ""
    for field in dict_foo.keys():
        query = field
        # checks if the key is a dict
        if type(dict_foo[field]) == dict:
            if "tide.meta.definition" in dict_foo[field].keys():
                if (metadef := dict_foo[field]["tide.meta.definition"]) is True:
                    temp = OpenTide.TideSchemas.definitions[field]
                else:
                    temp = OpenTide.TideSchemas.definitions[metadef]

                if deprecation_message := dict_foo[field].get("tide.meta.deprecation"):
                    temp["title"] = "⚠️ DEPRECATION WARNING"
                    temp["description"] = "⚠️ DEPRECATED : " + deprecation_message

                dictionary[field] = temp

                gen_json_schema({field: dictionary[field]})

            else:
                title = dict_foo[field].get("title")

                if "icon" in dictionary[field].keys():
                    icon = dictionary[field]["icon"]
                else:
                    icon = get_icon(field)

                if title:
                    if icon:
                        dictionary[field]["title"] = f"{icon} {title}"
                    else:
                        dictionary[field]["title"] = title

                if deprecation_message := dict_foo[field].get("tide.meta.deprecation"):
                    dict_foo[field]["title"] = "⚠️ DEPRECATION WARNING"
                    dict_foo[field]["description"] = "⚠️ DEPRECATED : " + deprecation_message

                # If additionalProperties is not configured, we force it to
                # False. This prevents the users from adding invalid keys (
                # typos, or indentation error for example that
                # wouldn't be flagged by the validation, and not be processed
                # correctly.
                if dict_foo[field].get("type") == "object":
                    if not dict_foo[field].get("additionalProperties"):
                        dictionary[field]["additionalProperties"] = False

                # If within that dict a key is called coretide, the dict will receive
                # fields generated from the libraries to allow multi or single
                # field validation with JSON Schema
                if "recomposition" in dict_foo[field].keys():
                    temp = recomposition_handler(dict_foo[field]["recomposition"])
                    dictionary[field]["properties"] = temp

                # Handles retrieval of logsources
                if dict_foo[field].get("tide.config.visibility.logsources"):
                    logsources_result = VocabularyResolver.Logsources().resolve()
                    if logsources_result:
                        enums, descriptions = logsources_result
                        dictionary[field]["items"] = {}
                        dictionary[field]["items"]["enum"] = enums
                        dictionary[field]["items"]["markdownEnumDescriptions"] = descriptions
                        dictionary[field]["items"]["uniqueItems"] = True

                # Handles retrieval of detectors
                if dict_foo[field].get("tide.config.visibility.detectors"):
                    detectors_result = VocabularyResolver.Detectors().resolve()
                    if detectors_result:
                        enums, descriptions = detectors_result
                        if dict_foo[field].get("type") == "string":
                            dictionary[field]["enum"] = enums
                            dictionary[field]["markdownEnumDescriptions"] = descriptions
                        elif dict_foo[field].get("type") == "array":
                            dictionary[field]["items"] = {}
                            dictionary[field]["items"]["enum"] = enums
                            dictionary[field]["items"]["markdownEnumDescriptions"] = descriptions
                            dictionary[field]["items"]["uniqueItems"] = True

                # Handles the case when a list of values has to be fetched from
                # the configuration files.
                if config_fetch := dict_foo[field].get("tide.config.parameter-list"):
                    values_list = VocabularyResolver.Parameters(config_fetch).resolve()
                    if dict_foo[field].get("type") == "string":
                        dictionary[field]["enum"] = values_list
                    elif dict_foo[field].get("type") == "array":
                        dictionary[field]["items"] = {}
                        dictionary[field]["items"]["enum"] = values_list
                        dictionary[field]["items"]["uniqueItems"] = True

                # Handles the case where we want to dynamically return a list
                # of available systems
                if dict_foo[field].get("tide.config.systems::enabled"):
                    values_list = enabled_systems()
                    if dict_foo[field].get("type") == "string":
                        dictionary[field]["enum"] = values_list
                    elif dict_foo[field].get("type") == "array":
                        dictionary[field]["items"] = {}
                        dictionary[field]["items"]["enum"] = values_list
                        dictionary[field]["items"]["uniqueItems"] = True

                # Special handling to specifically get the available tenants
                if system := dict_foo[field].get("tide.config.system.tenants"):
                    values_list, descriptions_list = VocabularyResolver.SystemTenants(
                        system
                    ).resolve()
                    if dict_foo[field].get("type") == "string":
                        dictionary[field]["enum"] = values_list
                        dictionary[field]["markdownEnumDescriptions"] = descriptions_list
                    elif dict_foo[field].get("type") == "array":
                        dictionary[field]["items"] = {}
                        dictionary[field]["items"]["enum"] = values_list
                        dictionary[field]["items"]["uniqueItems"] = True
                        dictionary[field]["items"]["markdownEnumDescriptions"] = descriptions_list

                # Special handling to specifically get the available statuses
                if system := dict_foo[field].get("tide.config.statuses"):
                    values_list, descriptions_list = VocabularyResolver.Statuses().resolve()
                    if dict_foo[field].get("type") == "string":
                        dictionary[field]["enum"] = values_list
                        dictionary[field]["markdownEnumDescriptions"] = descriptions_list
                    elif dict_foo[field].get("type") == "array":
                        dictionary[field]["items"] = {}
                        dictionary[field]["items"]["enum"] = values_list
                        dictionary[field]["items"]["uniqueItems"] = True
                        dictionary[field]["markdownEnumDescriptions"] = descriptions_list

                # Handles vocabularies
                if vocab := dict_foo[field].get("tide.vocab"):
                    if type(vocab) is str:
                        # Add icon if available to title
                        icon = get_icon(query)
                        if icon:
                            dictionary[field]["title"] = icon + " " + dictionary[field]["title"]
                    if type(vocab) is bool:
                        vocab = field
                    scoped = dict_foo[field].get("tide.vocab.scoped")
                    hint_no_wrap = dict_foo[field].get("tide.vocab.hints.no-wrap")
                    stages = dict_foo[field].get("tide.vocab.stages")

                    # Normalize vocabs to list to support all variants
                    vocabs = [vocab] if type(vocab) is not list else vocab

                    temp = {}
                    enum = []
                    markdown_enum = []
                    for vocab in vocabs:
                        new_enum, new_markdown_enum = VocabularyResolver.Vocabulary(
                            vocab,
                            stages=stages,
                            no_wrap=hint_no_wrap,
                            scoped=scoped,
                        ).resolve()
                        enum.extend(new_enum)
                        markdown_enum.extend(new_markdown_enum)
                    temp["enum"] = enum
                    temp["markdownEnumDescriptions"] = markdown_enum

                    # When no field type is present, assume it's a direct string
                    # When the type is set to string, oneOf allows only one value
                    # to be selected
                    field_types = dict_foo[field].get("type")
                    if field_types:
                        field_types = [field_types] if isinstance(field_types, str) else field_types
                    if field_types is None or "string" in field_types:
                        dictionary[field].update(temp)
                    elif "array" in field_types:
                        dictionary[field]["items"] = temp
                        dictionary[field]["uniqueItems"] = True

                else:
                    gen_json_schema(dictionary[field])

    return dictionary


def run():

    log("TITLE", "Metaschema to JSON Schema Assembler")
    log(
        "INFO",
        "Generates JSON Schemas from metaschema files, dynamically "
        "looking up Vocabulary values. JSON Schemas allow to validate the models "
        "as per the CoreTIDE schema.",
    )

    # Loops through all source yaml defined in meta_to_json and generates the
    # corresponding json structure before writing to the associated output file
    for meta in GLOBAL_CONFIG.metaschemas:
        if meta in GLOBAL_CONFIG.json_schemas:
            yaml_input = METASCHEMAS_FOLDER / GLOBAL_CONFIG.metaschemas[meta]
            json_output = JSON_SCHEMA_FOLDER / GLOBAL_CONFIG.json_schemas[meta]

            parsing = yaml.safe_load(open(yaml_input, encoding="utf-8"))
            placeholders = parsing.get("tide.placeholders") or {}

            log("ONGOING", "Generating json schema for : " + str(yaml_input))

            # Generate Schema
            generated = gen_json_schema(parsing)

            # Removes the OpenTide reserved schema keys
            cleaned = strip_framework_keywords(generated)

            # Export JSON Schemas
            log("ONGOING", "Exporting generated schema to : " + str(json_output))
            output = json.dumps(cleaned, indent=4, sort_keys=False, default=str)
            for placeholder in placeholders:
                log(
                    "ONGOING",
                    f"Replacing all occurence of placeholder {placeholder} with value {placeholders[placeholder]}",
                )
                output = output.replace(f"${placeholder}", placeholders[placeholder])

            output_file = open((json_output), "w", encoding="utf-8")
            output_file.write(output)
            output_file.close()
            log("SUCCESS", "Correctly exported")

    log("SUCCESS", "Generated all JSON Schemas")

    # Configuration Schemas
    # Configuration meta schemas live under Configurations/ subdirectories
    # and may use tide.* keywords for vocabulary resolution
    config_metaschemas = GLOBAL_CONFIG.config_metaschemas
    config_json_schemas = GLOBAL_CONFIG.config_json_schemas

    if config_metaschemas:
        log("TITLE", "Configuration Schema Assembler")
        log(
            "INFO",
            "Generates JSON Schemas from configuration meta schema files, "
            "dynamically looking up Vocabulary values where applicable.",
        )

        for meta in config_metaschemas:
            if meta in config_json_schemas:
                yaml_input = METASCHEMAS_FOLDER / config_metaschemas[meta]
                json_output = JSON_SCHEMA_FOLDER / config_json_schemas[meta]

                parsing = yaml.safe_load(open(yaml_input, encoding="utf-8"))
                placeholders = parsing.get("tide.placeholders") or {}

                log("ONGOING", "Generating config schema for : " + str(yaml_input))

                # Generate Schema (resolves tide.vocab and other tide.* keywords)
                generated = gen_json_schema(parsing)

                # Removes the OpenTide reserved schema keys
                cleaned = strip_framework_keywords(generated)

                # Export JSON Schemas
                log("ONGOING", "Exporting generated schema to : " + str(json_output))
                output = json.dumps(cleaned, indent=4, sort_keys=False, default=str)
                for placeholder in placeholders:
                    log(
                        "ONGOING",
                        f"Replacing all occurence of placeholder {placeholder} with value {placeholders[placeholder]}",
                    )
                    output = output.replace(f"${placeholder}", placeholders[placeholder])

                output_file = open((json_output), "w", encoding="utf-8")
                output_file.write(output)
                output_file.close()
                log("SUCCESS", "Correctly exported")

        log("SUCCESS", "Generated all Configuration Schemas")


if __name__ == "__main__":
    run()
