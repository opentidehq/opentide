"""``opentide deploy migrate-state``: move vendor rule ids off rules (RFC 0010 §3).

Defender for Endpoint, SentinelOne and CrowdStrike ids found on a rule are
written to ``.opentide/states/deployment/<uuid>.json`` first, durably, and only
then removed from the YAML. A crash between the two leaves both copies; they
agree, so the next run strips the YAML and succeeds.

The YAML edit deletes whole lines located from the parsed node marks: the
``rule_id::<tenant>`` line, or the ``rule_id`` / ``rule_id_bundle`` key and
every line of its mapping. Nothing else is rewritten, so comments, key order
and whitespace survive. The edited text is parsed again and must equal the
original document minus those keys, or the rule is left alone.

Every other platform (Sentinel, Splunk, HarfangLab, Carbon Black Cloud, ...)
addresses its rules without a vendor id, so its keys are removed and reported
as ``external_id_unused`` (platform, tenant, value, file), not copied into a
shard. The command never calls a vendor API.

Exit codes: ``0`` after a migration, a clean second run, or
``external_id_unused`` warnings only; ``1`` when any rule fails or the
deployment state directory is gitignored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from opentide.core.logging import get_logger
from opentide.states.deployment import (
    LEGACY_MAP_KEYS,
    LEGACY_TENANT_PREFIX,
    STATE_PLATFORMS,
    DeploymentState,
    DeploymentStateError,
    deployment_state_ignore,
    ignored_message,
    is_legacy_external_id_key,
    normalise_external_id,
    shard_path,
    write_durable,
)

logger = get_logger(__name__)

COMMIT_ADVICE = (
    "Commit the edited rules together with every new or changed file under "
    ".opentide/states/deployment/. A deploy from a checkout that has the stripped "
    "rules but not the shards creates a second remote rule."
)

_UNSUPPORTED_BREAKS = re.compile("\r(?!\n)|[\x85\u2028\u2029]")


@dataclass(frozen=True)
class Binding:
    """One vendor id found on a rule."""

    platform: str
    tenant: str
    value: object
    stored: str

    def as_dict(self) -> dict[str, str]:
        return {"platform": self.platform, "tenant": self.tenant, "external_id": self.stored}


@dataclass
class RuleIds:
    """Everything one rule file needs moved, or why it cannot be."""

    path: Path
    object_uuid: str | None = None
    bindings: list[Binding] = field(default_factory=list)
    spans: list[tuple[int, int]] = field(default_factory=list)
    removed: list[tuple[str, str]] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)

    def fail(self, code: str, message: str) -> None:
        self.errors.append((code, message))


def _rule_files(rules_dir: Path) -> list[Path]:
    if not rules_dir.is_dir():
        return []
    found = [*rules_dir.rglob("*.yaml"), *rules_dir.rglob("*.yml")]
    return sorted(path for path in found if path.is_file())


def _mapping_get(node: yaml.Node, key: str) -> yaml.Node | None:
    if not isinstance(node, yaml.MappingNode):
        return None
    for key_node, value_node in node.value:
        if isinstance(key_node, yaml.ScalarNode) and key_node.value == key:
            return value_node
    return None


def _last_line(node: yaml.Node) -> int:
    """Zero-based last line *node* occupies."""
    start, end = node.start_mark, node.end_mark
    assert start is not None and end is not None, "composed nodes always carry marks"
    if isinstance(node, yaml.ScalarNode):
        if end.column == 0 and end.line > start.line:
            return end.line - 1
        return end.line
    if isinstance(node, (yaml.MappingNode, yaml.SequenceNode)) and not node.flow_style:
        children: list[yaml.Node] = []
        if isinstance(node, yaml.MappingNode):
            for key_node, value_node in node.value:
                children.extend((key_node, value_node))
        else:
            children.extend(node.value)
        if children:
            return max(_last_line(child) for child in children)
    return end.line


def _construct(node: yaml.Node) -> Any:
    loader = yaml.SafeLoader("")
    try:
        return loader.construct_object(node, deep=True)
    finally:
        loader.dispose()


def _bind(rule: RuleIds, platform: str, tenant: object, value: object, seen: set) -> None:
    if not isinstance(tenant, str) or tenant.strip() == "":
        rule.fail(
            "external_id_shape", f"{platform}: tenant name {tenant!r} is empty or not a string"
        )
        return
    tenant_name = tenant.strip()
    try:
        stored = normalise_external_id(platform, value)
    except DeploymentStateError as error:
        rule.fail(error.code, f"{platform} tenant {tenant_name!r}: {error.message}")
        return
    if (platform, tenant_name) in seen:
        rule.fail(
            "external_id_conflict",
            f"{platform} tenant {tenant_name!r} is mapped more than once on the rule",
        )
        return
    seen.add((platform, tenant_name))
    rule.bindings.append(Binding(platform, tenant_name, value, stored))


def _collect(rule: RuleIds, root: yaml.Node) -> None:
    configurations = _mapping_get(root, "configurations")
    if not isinstance(configurations, yaml.MappingNode):
        return
    seen: set[tuple[str, str]] = set()
    for platform_node, block in configurations.value:
        if not isinstance(block, yaml.MappingNode):
            continue
        platform = str(platform_node.value)
        for key_node, value_node in block.value:
            key = key_node.value if isinstance(key_node, yaml.ScalarNode) else None
            if not is_legacy_external_id_key(key):
                continue
            assert isinstance(key, str)
            rule.removed.append((platform, key))
            assert key_node.start_mark is not None
            rule.spans.append((key_node.start_mark.line, _last_line(value_node)))
            if key in LEGACY_MAP_KEYS:
                if not isinstance(value_node, yaml.MappingNode):
                    rule.fail(
                        "external_id_shape",
                        f"configurations.{platform}.{key} is not a mapping of tenant to id",
                    )
                    continue
                for tenant_node, id_node in value_node.value:
                    if not isinstance(id_node, yaml.ScalarNode):
                        rule.fail(
                            "external_id_shape",
                            f"configurations.{platform}.{key}: the id is not a scalar",
                        )
                        continue
                    _bind(rule, platform, _construct(tenant_node), _construct(id_node), seen)
            else:
                if not isinstance(value_node, yaml.ScalarNode):
                    rule.fail(
                        "external_id_shape",
                        f"configurations.{platform}.{key}: the id is not a scalar",
                    )
                    continue
                tenant = key[len(LEGACY_TENANT_PREFIX) :]
                _bind(rule, platform, tenant, _construct(value_node), seen)


def _strip_lines(text: str, spans: list[tuple[int, int]]) -> str:
    # Split on LF only (CRLF lines keep their CR), matching PyYAML's line marks.
    lines = re.split(r"(?<=\n)", text)
    drop: set[int] = set()
    for start, end in spans:
        drop.update(range(start, end + 1))
    return "".join(line for number, line in enumerate(lines) if number not in drop)


def _expected_document(original: Any) -> Any:
    configurations = original.get("configurations") if isinstance(original, dict) else None
    if isinstance(configurations, dict):
        for block in configurations.values():
            if isinstance(block, dict):
                for key in [k for k in block if is_legacy_external_id_key(k)]:
                    del block[key]
    return original


def _plan_rule(path: Path) -> tuple[RuleIds, str | None]:
    """Find the ids in one file and compute its edited text."""
    rule = RuleIds(path=path)
    try:
        # Bytes, not read_text(): universal newlines would turn CRLF into LF.
        text = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        rule.fail("yaml_parse", f"cannot read {path}: {exc}")
        return rule, None
    if "rule_id" not in text:
        return rule, None
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as exc:
        rule.fail("yaml_parse", f"cannot parse {path}: {exc}")
        return rule, None
    if root is None:
        return rule, None
    _collect(rule, root)
    if not rule.removed:
        return rule, None
    metadata = _mapping_get(root, "metadata")
    uuid_node = _mapping_get(metadata, "uuid") if metadata is not None else None
    raw_uuid = _construct(uuid_node) if isinstance(uuid_node, yaml.ScalarNode) else None
    if any(binding.platform in STATE_PLATFORMS for binding in rule.bindings):
        try:
            rule.object_uuid = shard_path(raw_uuid).stem
        except DeploymentStateError:
            rule.fail("invalid_uuid", f"metadata.uuid {raw_uuid!r} is not a UUID")
    elif raw_uuid is not None:
        rule.object_uuid = str(raw_uuid)
    if rule.errors:
        return rule, None
    if _UNSUPPORTED_BREAKS.search(text):
        rule.fail(
            "external_id_shape",
            "the file uses line breaks other than LF or CRLF; remove the keys by hand",
        )
        return rule, None
    edited = _strip_lines(text, rule.spans)
    try:
        reparsed = yaml.safe_load(edited)
        expected = _expected_document(yaml.safe_load(text))
    except yaml.YAMLError:
        reparsed, expected = None, object()
    if reparsed != expected:
        keys = ", ".join(f"configurations.{p}.{k}" for p, k in rule.removed)
        rule.fail(
            "external_id_shape",
            f"{keys} cannot be removed without rewriting other content "
            "(flow-style block?); remove the keys by hand",
        )
        return rule, None
    return rule, edited


def _check_shard(rule: RuleIds, workspace: Path) -> DeploymentState | None:
    """Load the shard and refuse ids that disagree with it."""
    shard_bindings = [b for b in rule.bindings if b.platform in STATE_PLATFORMS]
    if not shard_bindings or rule.object_uuid is None:
        return None
    try:
        state = DeploymentState.load(rule.object_uuid, workspace)
    except DeploymentStateError as error:
        rule.fail(error.code, error.message)
        return None
    for binding in shard_bindings:
        existing = state.get(binding.platform, binding.tenant)
        if existing is not None and existing != binding.stored:
            rule.fail(
                "external_id_conflict",
                f"{binding.platform} tenant {binding.tenant!r} is {binding.stored!r} on the "
                f"rule but {existing!r} in {state.path}",
            )
    return state


def run_migrate_state(workspace: Path, rules_dir: Path) -> dict[str, object]:
    """Move every vendor id under *rules_dir* into deployment state shards."""
    ignore = deployment_state_ignore(workspace)
    if ignore is not None:
        return {
            "status": "failed",
            "code": "deployment_state_ignored",
            "message": "deployment_state_ignored: " + ignored_message(ignore),
            "ignore": {"pattern": ignore.pattern, "source": ignore.source, "line": ignore.line},
            "advice": (
                "Edit .gitignore so it ignores .opentide/states/sharing.jsonl only, then re-run"
            ),
            "migrated": [],
            "unused": [],
            "errors": [],
            "_exit_code": 1,
        }

    migrated: list[dict[str, object]] = []
    unused: list[dict[str, object]] = []
    errors: list[dict[str, object]] = []
    shards_written = 0

    for path in _rule_files(rules_dir):
        rule, edited = _plan_rule(path)
        state = _check_shard(rule, workspace) if edited is not None else None
        relative = _display(path, workspace)
        if rule.errors:
            for code, message in rule.errors:
                logger.error(code, detail=message, file=relative, uuid=rule.object_uuid)
                errors.append(
                    {"code": code, "file": relative, "uuid": rule.object_uuid, "message": message}
                )
            continue
        if edited is None:
            continue

        for binding in rule.bindings:
            if binding.platform in STATE_PLATFORMS:
                continue
            logger.warning(
                "external_id_unused",
                platform=binding.platform,
                tenant=binding.tenant,
                value=binding.stored,
                file=relative,
            )
            unused.append({"file": relative, "uuid": rule.object_uuid, **binding.as_dict()})

        shard_bindings = [b for b in rule.bindings if b.platform in STATE_PLATFORMS]
        shard_file: str | None = None
        try:
            if state is not None and shard_bindings:
                changed = False
                for binding in shard_bindings:
                    if state.get(binding.platform, binding.tenant) != binding.stored:
                        state.set(binding.platform, binding.tenant, binding.stored)
                        changed = True
                if changed:
                    state.save()
                    shards_written += 1
                shard_file = _display(state.path, workspace)
            write_durable(path, edited)
        except (OSError, DeploymentStateError) as exc:
            message = f"could not write the migration for {relative}: {exc}"
            logger.error("deployment_state_write_failed", detail=message)
            errors.append(
                {
                    "code": "deployment_state_write_failed",
                    "file": relative,
                    "uuid": rule.object_uuid,
                    "message": message,
                }
            )
            continue
        logger.info("external_ids_migrated", file=relative, shard=shard_file)
        migrated.append(
            {
                "file": relative,
                "uuid": rule.object_uuid,
                "shard": shard_file,
                "bindings": [b.as_dict() for b in shard_bindings],
                "removed": [f"configurations.{p}.{k}" for p, k in rule.removed],
            }
        )

    ids = sum(len(item["bindings"]) for item in migrated)  # ty: ignore[invalid-argument-type]
    result: dict[str, object] = {
        "migrated": migrated,
        "unused": unused,
        "errors": errors,
        "shards_written": shards_written,
        "rules_edited": len(migrated),
        "_summary": {"ids": ids, "rules": len(migrated), "shards": shards_written},
    }
    if errors:
        result.update(
            status="failed",
            message=(
                f"{len(errors)} rule file(s) could not be migrated; "
                f"{len(migrated)} migrated. Fix them and re-run"
            ),
            detail="; ".join(f"{e['code']}: {e['file']}: {e['message']}" for e in errors),
            _exit_code=1,
        )
    elif migrated:
        result.update(
            status="completed",
            message=(
                f"Moved {_count(ids, 'vendor id')} to .opentide/states/deployment/ · "
                f"{_count(len(migrated), 'rule')} edited, "
                f"{_count(shards_written, 'shard')} written"
            ),
            advice=COMMIT_ADVICE,
        )
    else:
        result.update(status="completed", message="No vendor rule ids left on rules")
    if unused:
        result["warnings"] = [
            f"external_id_unused: {u['platform']} tenant {u['tenant']} id {u['external_id']} "
            f"removed from {u['file']} (never read by its deployer; not stored)"
            for u in unused
        ]
    return result


def _count(number: int, noun: str) -> str:
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"


def _display(path: Path, workspace: Path) -> str:
    try:
        return path.resolve().relative_to(workspace.resolve()).as_posix()
    except ValueError:
        return str(path)
