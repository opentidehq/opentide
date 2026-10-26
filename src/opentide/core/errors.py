"""opentide's exception types."""

from __future__ import annotations

import re
from pathlib import Path


class Errors(Exception):
    """
    Container for all custom opentide errors
    """

    class TideDataModelErrors(Exception):
        """
        Represent all errors related to malformed Tide Objects
        """

    class TideDeploymentErrors(Exception):
        """
        Represents all errors occuring during a deployment procedure
        """

    class TenantConnectionError(Exception):
        """
        Raised when failed to establish a connection to the target tenant
        """

    class DetectionRulesOperationErrors(TideDeploymentErrors):
        """
        Represents all errors related to Detection Rules API operations
        """

    class DetectionRuleCreationFailed(Exception):
        """
        Raised when failed to create a detection rule in the target tenant
        """

    class DetectionRuleUpdateFailed(DetectionRulesOperationErrors):
        """
        Raised when failed to update a detection rule in the target tenant
        """

    class DetectionRuleDisablingFailed(DetectionRulesOperationErrors):
        """
        Raised when failed to update a detection rule in the target tenant
        """

    class DetectionRuleDeletionFailed(DetectionRulesOperationErrors):
        """
        Raised when failed to delete a detection rule in the target tenant
        """

    class TideConfigurationErrors(Exception):
        """
        Represents all errors related to opentide Configuration Files
        """

    class TideSystemConfigurationErrors(TideConfigurationErrors):
        """
        Represents all errors related to opentide Configuration Files
        """

    class TideTenantConfigurationErrors(TideSystemConfigurationErrors):
        """
        Represents all errors related to opentide System Configuration Files
        """

    class TideTenantConfigurationMissingPermissions(TideSystemConfigurationErrors):
        """
        Represents all errors related to API permissions on target systems
        """

    class TenantNonExistingDeploymentPlan(TideTenantConfigurationErrors):
        """
        Raised when a tenant uses a non existing deployment plan
        """

    class TideMDRDataModelErrors(TideDataModelErrors):
        """
        Raised for all errors related to incorrect MDR Data Structures
        """

    class TideQueryValidationError(Exception):
        """
        Raised when the MDR query failed validation
        """


TideErrors = Errors


_TOML_POSITION = re.compile(r"\s*\(at line (\d+), column (\d+)\)\s*$")
_TOML_END = re.compile(r"\s*\(at end of document\)\s*$")


#: The ``help`` line for an object file that is not one mapping.
OBJECT_FILE_HELP = "an object file is one mapping of keys such as name, metadata and description"


class UserFileError(ValueError):
    """A file of the user's that opentide cannot read: theirs to fix, not a crash.

    The CLI reports it as a diagnostic with :attr:`code` that points at the
    file, line and column, and exits 1. *line* and *column* are 1-based, or
    ``None`` when the parser gave no position.
    """

    #: The diagnostic code, and the JSON ``failure.code``.
    code = "user_file"
    #: What the diagnostic's message starts with, if anything.
    title = "Could not read"
    #: The ``help`` line under the frame.
    help = "fix the file at this position, then run the command again"
    #: The outcome line.
    outcome = "1 file could not be read"

    def __init__(
        self,
        path: Path,
        problem: str,
        *,
        line: int | None = None,
        column: int | None = None,
        end_column: int | None = None,
    ) -> None:
        self.path = path
        self.problem = problem
        self.line = line
        self.column = column
        #: Exclusive; one past *column* when not given.
        self.end_column = end_column
        where = "" if line is None else f":{line}" + ("" if column is None else f":{column}")
        super().__init__(f"{path}{where}: {problem}")


class ConfigFileError(UserFileError):
    """A workspace configuration file that does not parse."""

    code = "config_parse"
    title = "Could not parse configuration TOML"
    help = "fix the TOML syntax at this position, then run the command again"
    outcome = "1 configuration file does not parse"

    @classmethod
    def from_toml(cls, path: Path, exc: ValueError) -> ConfigFileError:
        """From a ``TOMLDecodeError``, which puts its position at the end of its message."""
        problem = str(getattr(exc, "msg", None) or exc)
        line = getattr(exc, "lineno", None)
        column = getattr(exc, "colno", None)
        if match := _TOML_POSITION.search(problem):
            problem = problem[: match.start()]
            line, column = line or int(match.group(1)), column or int(match.group(2))
        problem = _TOML_END.sub("", problem)
        return cls(path, problem, line=line, column=column)


class ObjectFileError(UserFileError):
    """An object file whose YAML is not one mapping, found outside ``validate``."""

    code = "yaml_parse"
    title = ""
    help = OBJECT_FILE_HELP
    outcome = "1 object file could not be loaded"
