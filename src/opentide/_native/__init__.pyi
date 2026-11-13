"""Type stubs for the compiled module. Keep in step with ``src/lib.rs``."""

from collections.abc import Sequence
from typing import Final, Literal, final

# The Tide models (UC-1.9), whose stub `cargo xtask stubs` generates.
from opentide._native import models as models

# The SDK's core (UC-5.2): the facade's Workspace and run_json.
from opentide._native import sdk as sdk

Severity = Literal["error", "warning", "information", "hint"]
Language = Literal["kql", "spl", "esql", "eql", "kuery", "lucene", "falco", "cql", "opentide-yaml"]

#: The version of the language-server crates (opentide-analysis) compiled in.
ENGINE_VERSION: Final[str]
#: Every diagnostic code the engine can emit.
CODES: Final[list[str]]
#: Every language id ``highlight`` accepts; ``analyze_query`` takes each but ``opentide-yaml``.
LANGUAGES: Final[list[str]]

@final
class Diagnostic:
    @property
    def code(self) -> str: ...
    @property
    def severity(self) -> Severity: ...
    @property
    def message(self) -> str: ...
    @property
    def line(self) -> int: ...
    @property
    def column(self) -> int: ...
    @property
    def end_line(self) -> int: ...
    @property
    def end_column(self) -> int: ...
    @property
    def field_path(self) -> list[str] | None: ...
    @property
    def suggestion(self) -> str | None: ...

def analyze_query(
    text: str, language: str, platform: str | None = None, stack: str | None = None
) -> list[Diagnostic]: ...
def highlight(text: str, language: str) -> list[tuple[int, int, int, int, str]]: ...
def describe_code(code: str) -> str | None: ...
def language_for_path(path: str) -> Language | None: ...
def cli_main(argv: Sequence[str], version: str) -> int: ...
