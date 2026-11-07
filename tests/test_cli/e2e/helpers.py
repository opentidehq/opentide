"""Shared helpers for CLI E2E tests that author objects from docs."""

from __future__ import annotations

import importlib
import re
import sys
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from importlib.machinery import ModuleSpec
from pathlib import Path
from types import ModuleType

#: What the removed default plan (FULL) did: read every rule file and run both
#: deployable strategies, so every deployable rule is selected.
EVERY_RULE = ("--strategy", "PREVIEW", "--strategy", "RELEASE", "--all")


def sdk_installed(module: str) -> bool:
    """Whether *module* can actually be imported.

    ``importlib.util.find_spec`` raises when a parent package is absent, which
    is the common case here: these tests exist to prove the no-extras path.
    """
    try:
        importlib.import_module(module)
    except ImportError:
        return False
    return True


class _Blocker:
    """A meta-path finder that refuses a set of package prefixes."""

    def __init__(self, prefixes: Sequence[str]) -> None:
        self._prefixes = tuple(prefixes)

    def _blocks(self, name: str) -> bool:
        return any(name == p or name.startswith(f"{p}.") for p in self._prefixes)

    def find_spec(self, fullname: str, path: object = None, target: object = None) -> ModuleSpec:
        if self._blocks(fullname):
            raise ModuleNotFoundError(f"No module named {fullname!r}", name=fullname)
        return None  # type: ignore[return-value]


@contextmanager
def hidden_modules(*prefixes: str, purge: Sequence[str] = ()) -> Iterator[None]:
    """Make *prefixes* unimportable for the duration of the block.

    Tests for the no-extras path used to skip themselves when the SDK happened
    to be installed, so the branch they exist to cover ran only on machines
    that lacked the extra. Blocking the import instead makes the path
    deterministic wherever the suite runs.

    ``purge`` drops modules from the cache without blocking them, so a module
    that binds a hidden SDK at import time is re-imported under the block
    rather than served from an earlier, successful import. Afterwards the
    modules from before the block are back, on ``sys.modules`` and on their
    parent packages alike.
    """
    blocker = _Blocker(prefixes)
    purge_all = _Blocker(purge)
    saved: dict[str, ModuleType] = {
        name: module
        for name, module in sys.modules.items()
        if blocker._blocks(name) or purge_all._blocks(name)
    }
    for name in saved:
        del sys.modules[name]
    sys.meta_path.insert(0, blocker)  # type: ignore[arg-type]
    try:
        yield
    finally:
        sys.meta_path.remove(blocker)  # type: ignore[arg-type]
        imported = {name: module for name, module in sys.modules.items() if purge_all._blocks(name)}
        for name in imported:
            del sys.modules[name]
        sys.modules.update(saved)
        _unbind_from_parents(imported)


def _unbind_from_parents(dropped: Mapping[str, ModuleType]) -> None:
    """Undo the parent bindings of modules imported in a ``hidden_modules`` block.

    Importing ``a.b`` also sets ``a.b`` as an attribute of ``a``. When ``a`` was not
    purged, the copy of ``b`` imported in the block stayed reachable from it after
    ``sys.modules`` was restored, without the submodules of the original ``b``:
    ``monkeypatch.setattr("a.b.c.X", ...)`` in any later test of that process then
    raised ``AttributeError``, or patched a copy no code used. Each such binding
    points at the restored module again, or goes when there is none.
    """
    for name, module in dropped.items():
        parent_name, _, child = name.rpartition(".")
        parent = sys.modules.get(parent_name)
        if parent is None or getattr(parent, child, None) is not module:
            continue
        restored = sys.modules.get(name)
        if restored is None:
            delattr(parent, child)
        else:
            setattr(parent, child, restored)


def uncomment_tenants(config: Path) -> None:
    """Uncomment the trailing ``#[[tenants]]`` example that setup and the corpus ship."""
    template, example = config.read_text(encoding="utf-8").split("#[[tenants]]")
    tenants = re.sub(r"^#", "", "#[[tenants]]" + example, flags=re.MULTILINE)
    config.write_text(template + tenants, encoding="utf-8")


ROOT = Path(__file__).resolve().parents[3]
TUTORIAL = ROOT / "docs" / "usage" / "tutorial.md"

TUTORIAL_FILES = (
    ("objects/threats/simulated-actor.yaml", "Create `objects/threats/simulated-actor.yaml`:"),
    (
        "objects/objectives/credential-access-objective.yaml",
        "Create `objects/objectives/credential-access-objective.yaml`:",
    ),
    ("objects/rules/sentinel-kql-rule.yaml", "Create `objects/rules/sentinel-kql-rule.yaml`:"),
)


def yaml_fence_after(markdown: str, heading: str) -> str:
    idx = markdown.index(heading)
    start = markdown.index("```yaml", idx)
    end = markdown.index("```", start + 7)
    return markdown[start + 7 : end].lstrip("\n")


def write_tutorial_objects(repo: Path, *, markdown: str | None = None) -> None:
    text = TUTORIAL.read_text(encoding="utf-8") if markdown is None else markdown
    for relpath, heading in TUTORIAL_FILES:
        dest = repo / relpath
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(yaml_fence_after(text, heading), encoding="utf-8")
