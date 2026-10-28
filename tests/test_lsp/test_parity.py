"""What ``opentide validate`` reports on an object, the language server reports too (#678).

The language server (editors, ``opentide lsp check``, ``opentide tui``) and
``opentide validate`` check the same objects. For every registered revision
of every object family, this starts from a valid object and derives variants
with one fault each, taken from the catalog of that revision: a required
field missing, a key the revision does not define (one another revision of
the family defines included), a vocabulary value that does not exist, a
malformed UUID. Every variant is one file of one workspace, so ``validate``
and ``lsp check`` each run once.

The assertion: each object-schema error ``validate`` reports on a variant,
the language server reports too, as an error on the same field. The
differences that are intended are listed in :data:`KNOWN_DIFFERENCES`, each
with its reason; a listed difference that is gone fails too, so the list
shrinks as the engine catches up.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml
from tests.test_cli.conftest import parse_cli_json
from tests.test_cli.e2e.helpers import TUTORIAL, write_tutorial_objects

from opentide.generation.lsp_catalog import fields_catalog

pytestmark = pytest.mark.cli_smoke

#: validate codes about an object's own shape and values: what the language
#: server must report too. Cross-object checks (references, duplicates) and
#: workspace policy are not compared.
SHAPE_CODES = frozenset(
    {"schema_validation", "schema_missing", "missing_uuid", "vocab_unknown", "invalid_uuid"}
)

#: ``(variant, field path)`` → why the language server does not report it.
KNOWN_DIFFERENCES: dict[tuple[str, str], str] = {}


@dataclass(frozen=True)
class Variant:
    """One object with one fault."""

    name: str
    family: str
    body: dict[str, Any]
    #: The field the fault is on; validate must report it.
    field: str


#: Where each family's objects live, and the file of the tutorial's.
FAMILIES = {
    "threat": ("objects/threats", "simulated-actor.yaml"),
    "objective": ("objects/objectives", "credential-access-objective.yaml"),
    "rule": ("objects/rules", "sentinel-kql-rule.yaml"),
}


@pytest.fixture(scope="module")
def catalog() -> dict[str, Any]:
    return fields_catalog("parity")


def _fields(catalog: dict[str, Any], schema: str) -> dict[str, dict[str, Any]]:
    return {row["path"]: row for row in catalog["fields"] if row["schema"] == schema}


def _get(body: dict[str, Any], path: str) -> Any:
    node: Any = body
    for part in path.split(".") if path else []:
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _parent(body: dict[str, Any], path: str) -> tuple[dict[str, Any] | None, str]:
    head, _, leaf = path.rpartition(".")
    node = _get(body, head) if head else body
    return (node if isinstance(node, dict) else None), leaf


Change = Callable[[dict[str, Any]], None]


def _remove(path: str) -> Change:
    def change(body: dict[str, Any]) -> None:
        parent, leaf = _parent(body, path)
        if parent is not None:
            parent.pop(leaf, None)

    return change


def _set(path: str, value: Any) -> Change:
    def change(body: dict[str, Any]) -> None:
        parent, leaf = _parent(body, path)
        if parent is not None:
            parent[leaf] = value

    return change


def _faults(
    catalog: dict[str, Any], schema: str, base: dict[str, Any]
) -> Iterator[tuple[str, str, Change]]:
    """``(label, faulty field, change)`` for one revision's baseline."""
    family = catalog["schemas"][schema]["family"]
    fields = _fields(catalog, schema)
    for path, row in fields.items():
        parent, leaf = _parent(base, path)
        if parent is None or leaf not in parent:
            continue
        if row["required"]:
            yield f"missing {path}", path, _remove(path)
        if (
            row["enum"]
            and not row["array"]
            and isinstance(parent[leaf], str)
            and path != "metadata.schema"
        ):
            yield f"bad value {path}", path, _set(path, "zz-not-a-value")
    for path in ["", *(path for path, row in fields.items() if row.get("closed"))]:
        if path and not isinstance(_get(base, path), dict):
            continue
        unknown = f"{path}.zz_unknown" if path else "zz_unknown"
        yield f"unknown {unknown}", unknown, _set(unknown, "x")
    others = {
        path
        for other, root in catalog["schemas"].items()
        if root["family"] == family and other != schema
        for path in _fields(catalog, other)
    }
    for path in sorted(others - set(fields)):
        parent, leaf = _parent(base, path)
        if parent is not None and leaf not in parent:
            yield f"other revision's {path}", path, _set(path, "2026-01-03")
    yield "malformed metadata.uuid", "metadata.uuid", _set("metadata.uuid", "not-a-uuid")


def _variants(catalog: dict[str, Any], baselines: dict[str, dict[str, Any]]) -> Iterator[Variant]:
    """Every revision's valid baseline, then each of its one-fault variants."""
    for schema, root in catalog["schemas"].items():
        family = root["family"]
        base = copy.deepcopy(baselines[family])
        base["metadata"]["schema"] = schema
        yield Variant(f"{schema}:valid", family, copy.deepcopy(base), "")
        for label, field, change in _faults(catalog, schema, base):
            body = copy.deepcopy(base)
            change(body)
            yield Variant(f"{schema}:{label}", family, body, field)


class _BlockDumper(yaml.SafeDumper):
    """Multi-line strings (queries, descriptions) as ``|`` blocks, as authors write them."""


def _block(dumper: yaml.SafeDumper, value: str) -> yaml.ScalarNode:
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


_BlockDumper.add_representer(str, _block)


def _dump(body: dict[str, Any]) -> str:
    return yaml.dump(body, Dumper=_BlockDumper, sort_keys=False, allow_unicode=True)


@dataclass(frozen=True)
class Run:
    variants: dict[str, Variant]
    #: File name → ``{(code, field path, severity)}`` for each checker.
    validate: dict[str, set[tuple[str, str, str]]]
    lsp: dict[str, set[tuple[str, str, str]]]


@pytest.fixture(scope="module")
def run(
    tmp_path_factory: pytest.TempPathFactory, catalog: dict[str, Any], invoke_cli_module: Any
) -> Run:
    root = tmp_path_factory.mktemp("parity")
    repo = root / "parity-detections"
    setup = invoke_cli_module(
        "setup", "--yes", "--name", "Parity", "--org", "Example Corp",
        "--platform", "sentinel", "--path", str(repo), repo=root,
    )  # fmt: skip
    assert setup.exit_code == 0, setup.stdout + setup.stderr
    write_tutorial_objects(repo, markdown=TUTORIAL.read_text(encoding="utf-8"))
    baselines = {
        family: yaml.safe_load((repo / folder / name).read_text(encoding="utf-8"))
        for family, (folder, name) in FAMILIES.items()
    }
    variants: dict[str, Variant] = {}
    for number, item in enumerate(_variants(catalog, baselines)):
        folder, _ = FAMILIES[item.family]
        kind = {"threat": 1, "objective": 2, "rule": 3}[item.family]
        metadata = item.body.get("metadata")
        if isinstance(metadata, dict) and metadata.get("uuid") == "not-a-uuid":
            metadata["uuid"] = f"not-a-uuid-{number}"
        elif isinstance(metadata, dict) and "uuid" in metadata:
            metadata["uuid"] = f"00000000-0000-4000-8{kind}00-{number:012d}"
        # An objective's signals carry UUIDs too: unique per variant.
        for index, signal in enumerate(_get(item.body, "objective.signals") or []):
            if isinstance(signal, dict) and "uuid" in signal:
                signal["uuid"] = f"00000000-0000-4000-899{index}-{number:012d}"
        file_name = f"variant-{number:03d}.yaml"
        (repo / folder / file_name).write_text(_dump(item.body), encoding="utf-8")
        variants[file_name] = item

    validated = parse_cli_json(invoke_cli_module("validate", repo=repo))
    report = validated.get("report") or {}
    by_validate: dict[str, set[tuple[str, str, str]]] = {}
    for issue in [*(report.get("issues") or []), *(report.get("warnings") or [])]:
        name = Path(str(issue.get("file_path") or "")).name
        field = ".".join(part for part in issue.get("field_path") or [] if not str(part).isdigit())
        by_validate.setdefault(name, set()).add((issue["code"], field, issue["severity"]))
    checked = parse_cli_json(invoke_cli_module("lsp", "check", repo=repo))
    by_lsp: dict[str, set[tuple[str, str, str]]] = {}
    for item in checked["diagnostics"]:
        name = Path(item["path"]).name
        field = ".".join(item.get("field_path") or [])
        by_lsp.setdefault(name, set()).add((item["code"], field, item["severity"]))
    return Run(variants, by_validate, by_lsp)


@pytest.fixture(scope="module")
def invoke_cli_module(tmp_path_factory: pytest.TempPathFactory) -> Callable[..., Any]:
    """The CLI in-process, as ``invoke_cli`` runs it, for a module-scoped workspace."""
    import os

    from tests.corpus_support import clear_runtime_caches
    from typer.testing import CliRunner

    from opentide.cli import app

    runner = CliRunner()
    cache = tmp_path_factory.mktemp("parity-cache")

    def invoke(*args: str, repo: Path) -> Any:
        env = {
            "OPENTIDE_REPO_ROOT": str(repo),
            "OPENTIDE_TIDE_WORKSPACE": str(repo),
            "OPENTIDE_CACHE_DIR": str(cache),
            "PATH": os.environ.get("PATH", ""),
        }
        clear_runtime_caches()
        return runner.invoke(app, ["--json", "--repo", str(repo), *args], env=env)

    return invoke


def _errors(found: set[tuple[str, str, str]]) -> set[tuple[str, str]]:
    return {(code, field) for code, field, severity in found if severity == "error"}


def test_every_revision_has_its_variants(run: Run, catalog: dict[str, Any]) -> None:
    """Each revision is exercised: its baseline and a fault of every kind."""
    for schema in catalog["schemas"]:
        prefix = f"{schema}:"
        labels = {
            v.name.removeprefix(prefix).split(" ")[0]
            for v in run.variants.values()
            if v.name.startswith(prefix)
        }
        assert {"valid", "missing", "unknown", "malformed"} <= labels, (schema, labels)
    assert len(run.variants) >= 100


def test_every_variant_is_a_fault_validate_reports(run: Run) -> None:
    """The variants are what they claim: validate finds each fault, and
    nothing on a valid object."""
    for name, variant in run.variants.items():
        shape = {(c, f) for c, f in _errors(run.validate.get(name, set())) if c in SHAPE_CODES}
        if not variant.field:
            assert shape == set(), (variant.name, shape)
            continue
        fields = {field for _, field in shape}
        # An object-level finding (no field: missing_uuid) covers any fault.
        assert any(
            field in ("", variant.field) or field.startswith(f"{variant.field}.")
            for field in fields
        ), (variant.name, shape, run.validate.get(name), run.lsp.get(name))


def test_the_language_server_reports_what_validate_reports(run: Run) -> None:
    missing: dict[tuple[str, str], set[tuple[str, str]]] = {}
    for name, variant in run.variants.items():
        lsp_fields = {field for _, field in _errors(run.lsp.get(name, set()))}
        for code, field in _errors(run.validate.get(name, set())):
            if code not in SHAPE_CODES:
                continue
            if field in lsp_fields or any(lsp.startswith(f"{field}.") for lsp in lsp_fields):
                continue
            # Object-level (missing_uuid): any error on the object answers it.
            if not field and lsp_fields:
                continue
            missing.setdefault((variant.name, field), set()).add((code, field))
    unexplained = {key: value for key, value in missing.items() if key not in KNOWN_DIFFERENCES}
    assert unexplained == {}, json.dumps(
        {f"{name} @ {field}": sorted(found) for (name, field), found in unexplained.items()},
        indent=2,
    )
    gone = sorted(key for key in KNOWN_DIFFERENCES if key not in missing)
    assert gone == [], f"listed as known but now reported: {gone}"


def test_a_valid_object_is_valid_for_both(run: Run) -> None:
    for name, variant in run.variants.items():
        if variant.field:
            continue
        assert _errors(run.validate.get(name, set())) == set(), variant.name
        assert _errors(run.lsp.get(name, set())) == set(), (variant.name, run.lsp.get(name))
