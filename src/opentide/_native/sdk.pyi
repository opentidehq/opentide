"""Type stubs for ``opentide._native.sdk`` (UC-5.2, #837).

Keep in step with ``bindings/python/src/sdk.rs``.

The SDK's core: the facade's ``Workspace`` and ``run_json``, each document as
JSON text in the command line's key order. ``opentide.sdk`` wraps it;
``tests/test_sdk/test_stubs.py`` holds this file to the module.
"""

from collections.abc import Sequence
from typing import final

class SdkError(Exception):
    """A call the SDK could not run: ``args`` is ``(code, message)``."""

@final
class Workspace:
    @staticmethod
    def open(path: str, cwd: str | None = None) -> Workspace: ...
    @staticmethod
    def from_files(root: str, files: Sequence[tuple[str, str]]) -> Workspace: ...
    @property
    def root(self) -> str: ...
    def validate(
        self,
        *,
        check: str | None = None,
        files: Sequence[str] = ...,
        uuids: Sequence[str] = ...,
        types: Sequence[str] = ...,
        strict: bool = False,
        queries: str | None = None,
    ) -> str: ...
    def lint(
        self, *, checks: Sequence[str] = ..., files: Sequence[str] = ..., strict: bool = False
    ) -> str: ...
    def info(self) -> str: ...
    def rules(self) -> str: ...
    def objectives(self) -> str: ...
    def threats(self) -> str: ...
    def catalog(self) -> str: ...
    def coverage(self, technique: str) -> str: ...
    def deploy_plan(
        self,
        *,
        strategies: Sequence[str] | None = None,
        uuids: Sequence[str] = ...,
        files: Sequence[str] = ...,
        platform: str | None = None,
        keep_deprecated: bool | None = None,
    ) -> tuple[str, str | None, bool]: ...

def run_json(argv: Sequence[str]) -> str: ...
