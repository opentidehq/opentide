from __future__ import annotations

from opentide.core.io import load_yaml
from opentide.core.logging import get_logger
from opentide.core.object_refs import object_uuid
from opentide.core.registry import OpenTide
from opentide.deployment.git_repo import local_rule_scope, modified_rule_scope, rules_folder_in_repo
from opentide.models.deployment_enums import DeploymentStrategy, StatusStrategy
from opentide.platforms.enabled import enabled_systems

logger = get_logger(__name__)

SYSTEMS_CONFIGS_INDEX = OpenTide.Configurations.Systems.Index
DEPRECATED_STATUSES = (StatusStrategy.DELETION, StatusStrategy.DISABLEMENT)
NESTED_RULES_ISSUE = "https://github.com/OpenTideHQ/opentide/issues/312"
NESTED_RULES_SHOWN = 5

__all__ = [
    "DEPRECATED_STATUSES",
    "SYSTEMS_CONFIGS_INDEX",
    "ExternalIdHelper",
    "Proxy",
    "check_status",
    "enabled_systems",
    "make_deploy_plan",
]


def _platform_status(block: object, *, system: str, rule: str, uuid: str) -> str:
    """Read a platform block's ``status``, naming the object when it is absent.

    This used to be ``conf_data[system]["status"]``. A rule whose platform
    block omitted ``status`` therefore failed with a bare ``KeyError``, which
    the CLI rendered as a FATAL panel containing the single word ``'status'``
    -- no file, no UUID, no field path, nothing to act on.

    The model now requires ``status``, so a rule that reaches here without one
    predates that rule or bypassed validation. Either way it should say which
    object is wrong.
    """
    if not isinstance(block, dict) or not block.get("status"):
        logger.critical(
            "platform_status_missing",
            detail=(
                f"Rule {rule!r} ({uuid}) has no 'status' in its {system} "
                "configuration block. Add a status, e.g. 'status: STAGING', "
                "then re-run 'opentide validate'."
            ),
            system=system,
            rule=rule,
            uuid=uuid,
        )
        raise KeyError(
            f"{rule!r} ({uuid}): configurations.{system}.status is required for deployment"
        )
    return str(block["status"])


def check_status(status_name: str) -> StatusStrategy:
    """Map a deployment status NAME to the strategy it carries.

    ``[[statuses]]`` in ``deployment.toml`` pairs a lifecycle label (``DESIGN``,
    ``PRODUCTION``) with a :class:`StatusStrategy` (``INERT``, ``RELEASE``).
    This resolves the label to the strategy, which is what the deploy planner
    filters on.
    """
    statuses_definitions = OpenTide.Configurations.Deployment.statuses
    for status in statuses_definitions:
        if status.name == status_name:
            if isinstance(status.strategy, StatusStrategy):
                return status.strategy
            if isinstance(status.strategy, str):
                # Was `StatusStrategy[status.name]` -- the status NAME, not its
                # strategy. No status name is a StatusStrategy member, so this
                # could only ever raise KeyError, never return. It was
                # unreachable because `DeploymentStatus.__post_init__` coerces
                # the string to the enum at load time, so a status built
                # outside that loader was the only way in.
                try:
                    return StatusStrategy[status.strategy]
                except KeyError as exc:
                    supported = ", ".join(member.name for member in StatusStrategy)
                    logger.critical(
                        "unknown_status_strategy",
                        status=status_name,
                        strategy=status.strategy,
                        supported=supported,
                    )
                    raise ValueError(
                        f"Status {status_name!r} declares an unknown strategy "
                        f"{status.strategy!r}. Use one of: {supported}."
                    ) from exc
            logger.critical(
                "could_not_return_status_strategy",
                detail=str(status),
                strategy_type=str(type(status.strategy)),
            )
            raise TypeError(
                f"Status {status_name!r} has a strategy of unsupported type "
                f"{type(status.strategy).__name__}; expected StatusStrategy or str."
            )

    available = ", ".join(status.name for status in statuses_definitions)
    logger.critical(
        "status_lookup_failed",
        detail=f"Requested status: {status_name}",
        available=available,
    )
    raise KeyError(
        f"Status {status_name!r} is not defined in deployment configuration. "
        f"Available statuses: {available}."
    )


def _nested_rules_warning(nested: tuple[str, ...]) -> str:
    folder = rules_folder_in_repo()
    names = ", ".join(nested[:NESTED_RULES_SHOWN])
    if len(nested) > NESTED_RULES_SHOWN:
        names += f", +{len(nested) - NESTED_RULES_SHOWN} more"
    return (
        f"{len(nested)} rule file(s) in subfolders of {folder} are not deployed "
        f"(deploy reads only files directly in {folder}; see {NESTED_RULES_ISSUE}): {names}"
    )


def _report_nested_rules(nested: tuple[str, ...], warnings: list[str] | None) -> None:
    fields = {"count": len(nested), "files": list(nested), "issue": NESTED_RULES_ISSUE}
    if warnings is None:
        logger.warning("deploy_nested_rules_skipped", **fields)
        return
    # The caller prints the message: a warning-level log would print it twice.
    logger.info("deploy_nested_rules_skipped", **fields)
    warnings.append(_nested_rules_warning(nested))


def make_deploy_plan(
    plan: DeploymentStrategy,
    wide_scope: bool = False,
    keep_deprecated: bool = True,
    *,
    warnings: list[str] | None = None,
) -> dict[str, list[str]]:
    """Assemble MDR UUIDs to deploy, organized per system.

    Only the files directly in the rules folder are deployed (#312). The
    message naming the skipped subfolder files is appended to *warnings*;
    without a list to report through, it is logged as a warning instead.
    """
    systems_deployment = enabled_systems()

    logger.info("compiling_deploy_plan", plan=plan.name, wide_scope=wide_scope)
    if wide_scope:
        logger.warning(
            "wide_scope_enabled",
            detail="Assembling plan without status filtering.",
        )

    deploy_mdr: dict[str, list[str]] = {}

    if plan is DeploymentStrategy.FULL:
        scope = local_rule_scope()
        logger.info("full_redeploy_scope", mdr_count=len(scope.files))
    else:
        scope = modified_rule_scope(plan)
    if scope.nested:
        _report_nested_rules(scope.nested, warnings)

    for rule in scope.files:
        data = load_yaml(rule)
        name = data["name"]
        conf_data = data["configurations"]
        mdr_uuid = object_uuid(data)

        for system in conf_data:
            platform_status = _platform_status(conf_data[system], system=system, rule=name, uuid=mdr_uuid)

            if system not in systems_deployment:
                # Not a failure: a catalogue may carry rules for platforms this
                # repository has not enabled. Errors here made skips look fatal.
                logger.warning(
                    "system_disabled_for_deploy",
                    system=system.upper(),
                    rule=name,
                    advice=f"enable it with 'opentide setup platforms --{system}'",
                )
                continue

            if keep_deprecated is False and check_status(platform_status) in DEPRECATED_STATUSES:
                logger.info(
                    "skip_deprecated_status",
                    system=system,
                    status=platform_status,
                )
                continue

            if wide_scope:
                deploy_mdr.setdefault(system, []).append(mdr_uuid)
                continue

            if plan is DeploymentStrategy.PRODUCTION:
                allowed = (
                    StatusStrategy.RELEASE,
                    StatusStrategy.UNIVERSAL,
                    StatusStrategy.DISABLEMENT,
                    StatusStrategy.DELETION,
                )
            elif plan is DeploymentStrategy.STAGING:
                allowed = (StatusStrategy.PREVIEW, StatusStrategy.UNIVERSAL)
            elif plan in (DeploymentStrategy.FULL, DeploymentStrategy.ALWAYS):
                allowed = (
                    StatusStrategy.RELEASE,
                    StatusStrategy.UNIVERSAL,
                    StatusStrategy.PREVIEW,
                    StatusStrategy.DISABLEMENT,
                    StatusStrategy.DELETION,
                )
            else:
                allowed = ()

            if check_status(platform_status) in allowed:
                deploy_mdr.setdefault(system, []).append(mdr_uuid)
                logger.info(
                    "mdr_selected_for_deploy",
                    system=system.upper(),
                    status=platform_status,
                    plan=plan.name,
                    rule=name,
                )
            else:
                logger.warning(
                    "mdr_skipped_for_plan",
                    system=system.upper(),
                    status=platform_status,
                    plan=plan.name,
                    rule=name,
                )

    return deploy_mdr


class Proxy:
    """Encapsulates proxy setup for environment variables."""

    @staticmethod
    def set_proxy() -> None:
        """Retired. Proxy configuration is ``opentide --proxy``."""
        return

    @staticmethod
    def unset_proxy() -> None:
        """Retired. An omitted ``--proxy`` leaves the process environment alone."""
        return


class ExternalIdHelper:
    """Utility class to help processing external rule IDs in MDR files."""

    @staticmethod
    def remove_id(rule_id: int | str, tenant_name: str, mdr_uuid: str) -> None:
        file_path = OpenTide.Configurations.Global.Paths.Tide.rule / OpenTide.Models.files[mdr_uuid]
        content = file_path.read_text(encoding="utf-8").splitlines(keepends=True)
        updated = [line for line in content if line.strip() != f"rule_id::{tenant_name}: {rule_id}"]
        file_path.write_text("".join(updated), encoding="utf-8")
        logger.info("external_id_removed", tenant=tenant_name)

    @staticmethod
    def insert_id(
        rule_id: int | str,
        tenant_name: str,
        mdr_uuid: str,
        system_name: str,
    ) -> None:
        file_path = OpenTide.Configurations.Global.Paths.Tide.rule / OpenTide.Models.files[mdr_uuid]
        content = file_path.read_text(encoding="utf-8").splitlines(keepends=True)
        updated: list[str] = []
        for line in content:
            if line.strip().removesuffix(":").strip() == system_name:
                updated.append(line)
                updated.append(f"    rule_id::{tenant_name}: {rule_id}\n")
            else:
                updated.append(line)

        file_path.write_text("".join(updated), encoding="utf-8")
        logger.info(
            "external_id_inserted",
            tenant=tenant_name,
            rule_id=str(rule_id),
        )
