"""Documentation domain types."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class DocumentFlavor(str, Enum):
    """Supported markdown rendering flavors."""

    github = "github"
    gitlab = "gitlab"
    azure_devops = "azure_devops"
    generic = "generic"


class DocumentScope(str, Enum):
    """Documentation generation scopes."""

    rules = "rules"
    objectives = "objectives"
    threats = "threats"
    index = "index"


@dataclass(frozen=True)
class DocumentRecord:
    """Single object tracked by the documentation catalog."""

    object_type: DocumentScope
    uuid: str
    name: str
    model: Any


@dataclass(frozen=True)
class PublishTarget:
    """Filesystem target for rendered markdown."""

    output_root: Path
    rules_dir: Path
    objectives_dir: Path
    threats_dir: Path
