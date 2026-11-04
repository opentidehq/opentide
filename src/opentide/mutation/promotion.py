"""Status promotion: move the platform blocks a deploy reached to the promotion target."""

import codecs
import json
import os
import sys
import tempfile
from collections.abc import Collection
from pathlib import Path

import yaml

from opentide.core.files import resolve_configurations
from opentide.core.logging import get_logger
from opentide.core.progress import report_stage
from opentide.core.runtime import is_debug
from opentide.deployment.git_repo import local_rule_files

logger = get_logger(__name__)

CONFIGURATIONS = resolve_configurations()

DEPLOYMENT_CONFIG = CONFIGURATIONS["deployment"]

PROMOTION_ENABLED = DEPLOYMENT_CONFIG["promotion"].get("enabled")
PROMOTION_TARGET = DEPLOYMENT_CONFIG["promotion"].get("promotion_target")

DEBUG = is_debug()


def get_valid_statuses() -> list[str]:
    """
    Retrieve a list of all valid status names from the deployment configuration.

    This function parses the deployment status configurations and returns a list
    of all defined status names, regardless of their strategy.

    Returns:
        list[str]: A list of all valid status names defined in the configuration.

    Raises:
        Exception: If the "statuses" configuration cannot be resolved from the deployment
                  configuration.
        Exception: If a status definition is missing the "name" field.

    Note:
        This function depends on a global CONFIGURATIONS dictionary containing deployment
        configuration with a "statuses" key that holds a list of status definitions.
        Each status definition must contain a "name" field.
    """
    statuses_config = CONFIGURATIONS["deployment"].get("statuses")
    if not statuses_config:
        raise Exception("Could not resolve status definitions")

    valid_statuses = []
    for status in statuses_config:
        name = status.get("name")
        if not name:
            raise Exception(f"Missing name in status definition: {status!s}")
        valid_statuses.append(name)
        logger.info("found_valid_status", detail=name)

    return valid_statuses


def get_non_promotable_statuses() -> list[str]:
    """
    Retrieve a list of status names that are considered non-promotable based on their strategy.
    This function parses the deployment status configurations and identifies statuses
    that have strategies of type "RELEASE", "DELETION", or "DISABLEMENT". These statuses
    are considered non-promotable and their names are collected into a list.
    Returns:
        list[str]: A list of status names that are non-promotable. Returns an empty list
                   if no non-promotable statuses are found.
    Raises:
        Exception: If the "statuses" configuration cannot be resolved from the deployment
                   configuration.
        Exception: If a status definition is missing the "strategy" field.
        Exception: If a status definition is missing the "name" field.
    Note:
        This function depends on a global CONFIGURATIONS dictionary containing deployment
        configuration with a "statuses" key that holds a list of status definitions.
        Each status definition must contain "name" and "strategy" fields.
    """
    non_editable_statuses = list()

    statuses_config = CONFIGURATIONS["deployment"].get("statuses")
    if not statuses_config:
        raise Exception("Could not resolve status definitions")

    for status in statuses_config:
        strategy = status.get("strategy")
        name = status.get("name")
        if not strategy:
            raise Exception("Missing strategy in status definition : ", str(status))

        if not name:
            raise Exception("Missing name in status definition : ", str(status))

        if strategy in ["RELEASE", "DELETION", "DISABLEMENT"]:
            logger.info("adding_status_as_a_non_promotable_status", detail=name)
            non_editable_statuses.append(name)

    return non_editable_statuses


# Get list of all valid statuses from configuration
VALID_STATUSES = get_valid_statuses()

# Get list of statuses that cannot be promoted
NON_PROMOTABLE_STATUSES = get_non_promotable_statuses()


class PromoteMDR:
    """
    If enabled by config, dynamically re-assigns non-production statuses
    towards new targets
    """

    def edit_mdr_statuses(self, mdr_path: Path, status_to_promote: list) -> None:
        """Rewrite each ``configurations.<platform>.status`` in *status_to_promote*.

        Only those scalars change, over the exact characters they occupy, so
        comments, quoting, key order, a byte-order mark and line endings
        survive. The text rewrite this replaces touched any ``status:`` line
        after any line containing ``configurations`` (a description, a comment,
        a nested ``status`` key), replaced the status as a substring, and wrote
        LF over CRLF files.
        """
        promoted = self.planned_statuses(mdr_path, status_to_promote)
        if promoted is not None:
            _write_atomically(mdr_path, promoted)
            logger.info("rule_promoted", path=str(mdr_path), target=PROMOTION_TARGET)

    def planned_statuses(self, mdr_path: Path, status_to_promote: list) -> bytes | None:
        """The promoted bytes of *mdr_path*, or ``None`` when nothing changes.

        A status this cannot rewrite safely (an anchor, an alias, a merge key)
        leaves the file as it is, with a warning naming it.
        """
        raw = mdr_path.read_bytes()
        bom = raw.startswith(codecs.BOM_UTF8)
        text = raw.decode("utf-8-sig")
        try:
            promoted = promote_block_statuses(text, status_to_promote, PROMOTION_TARGET)
        except PromotionRefused as exc:
            logger.warning(
                "rule_not_promoted",
                path=str(mdr_path),
                detail=str(exc),
                advice="Write each platform block's status as a plain value, then deploy again",
            )
            return None
        except (ValueError, yaml.YAMLError) as exc:
            raise ValueError(f"{mdr_path}: cannot promote its statuses: {exc}") from exc
        if promoted == text:
            return None
        return (codecs.BOM_UTF8 if bom else b"") + promoted.encode("utf-8")

    def promote(self, deployment: list[Path]):
        report_stage("status promotion")
        logger.info(
            "rule_promotion_started",
            detail="Promotes the status of modified rule files according to configuration",
        )

        if PROMOTION_ENABLED:
            if PROMOTION_TARGET not in VALID_STATUSES:
                logger.error(
                    "invalid_promotion_target",
                    target=PROMOTION_TARGET,
                    detail=f"Valid statuses: {', '.join(VALID_STATUSES)}",
                )
                sys.exit(1)

            if DEBUG:
                deployment = local_rule_files()

            else:
                # Fetch MDR in the deployment diff calculation
                # Returns string expression into list object
                if not deployment:
                    logger.info("found_nothing_to_deploy_in_pre_deployment_environment_variable")
                    return

            planned: list[tuple[Path, bytes]] = []
            for mdr in deployment:
                system_promotion = {}
                with open(mdr, encoding="utf-8") as mdr_file:
                    data = yaml.safe_load(mdr_file)
                mdr_name = data["name"]

                conf = data.get("configurations") if isinstance(data, dict) else None
                for system, block in (conf if isinstance(conf, dict) else {}).items():
                    system_status = block.get("status") if isinstance(block, dict) else None
                    if isinstance(system_status, str) and system_status not in (
                        NON_PROMOTABLE_STATUSES
                    ):
                        system_promotion[system] = system_status

                if not system_promotion:
                    logger.info(
                        "nothing_to_promote_rule_already_in_production_status", detail=mdr_name
                    )
                else:
                    logger.info(
                        "detected_statuses_needing_promotion_for_the_following_rule",
                        detail=mdr_name,
                    )
                    logger.info(
                        "promoting_the_following_systems_statuses",
                        detail=", ".join(
                            f"{key} : {value}" for key, value in system_promotion.items()
                        ),
                    )
                    statuses_to_replace = [system_promotion[s] for s in system_promotion]
                    promoted = self.planned_statuses(mdr, statuses_to_replace)
                    if promoted is not None:
                        planned.append((mdr, promoted))
            # Every file is planned before any is written: a file that cannot be
            # promoted fails the run with nothing half-promoted for the
            # write-back to commit.
            for mdr, promoted in planned:
                _write_atomically(mdr, promoted)
                logger.info("rule_promoted", path=str(mdr), target=PROMOTION_TARGET)

        else:
            logger.info(
                "rule_promotion_disabled_in_config",
                detail="Enable status promotion under [promotion] in deployment.toml",
            )


class PromotionRefused(ValueError):
    """A status promotion cannot rewrite without changing what else the file says."""


def promote_block_statuses(text: str, statuses: Collection[str], target: str) -> str:
    """*text* with each platform block ``status`` that is one of *statuses* set to *target*.

    Located through the composed node tree (``configurations`` at the root,
    then each platform mapping's own ``status`` key), never by line; the
    result is parsed again and must differ from the original by exactly those
    values, or :class:`ValueError` is raised and nothing is written.
    """
    root = yaml.compose(text)
    spans: list[tuple[int, int, str]] = []
    seen: set[int] = set()
    merge = "tag:yaml.org,2002:merge"
    if isinstance(root, yaml.MappingNode):
        for key, configurations in root.value:
            if key.value != "configurations" or not isinstance(configurations, yaml.MappingNode):
                continue
            for platform, block in configurations.value:
                if key.tag == merge or platform.tag == merge:
                    raise PromotionRefused("configurations uses a merge key (<<)")
                if not isinstance(block, yaml.MappingNode):
                    continue
                if any(field.tag == merge for field, _ in block.value):
                    raise PromotionRefused(f"configurations.{platform.value} uses a merge key (<<)")
                for field, value in block.value:
                    if not (
                        field.value == "status"
                        and isinstance(value, yaml.ScalarNode)
                        and value.tag == "tag:yaml.org,2002:str"
                        and value.value in statuses
                    ):
                        continue
                    # An alias is the anchored node itself, and an anchored
                    # scalar's span starts at its `&name`: rewriting either
                    # changes another value or breaks the alias.
                    if id(value) in seen or text[value.start_mark.index] in "&*":
                        raise PromotionRefused(
                            f"configurations.{platform.value}.status is an anchor or an alias"
                        )
                    seen.add(id(value))
                    spans.append((value.start_mark.index, value.end_mark.index, platform.value))
    if not spans:
        return text
    replacement = target if yaml.safe_load(target) == target else json.dumps(target)
    promoted = text
    for start, end, _ in sorted(spans, reverse=True):
        promoted = promoted[:start] + replacement + promoted[end:]
    expected = yaml.safe_load(text)
    for _, _, platform in spans:
        expected["configurations"][platform]["status"] = target
    if yaml.safe_load(promoted) != expected:
        raise PromotionRefused("promotion would change more than the platform statuses")
    return promoted


def _write_atomically(path: Path, data: bytes) -> None:
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
