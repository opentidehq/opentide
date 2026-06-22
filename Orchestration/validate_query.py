"""Thin wrapper — delegates to opentide CLI query validation."""

from opentide.cli.context import CliContext
from opentide.cli.services.validation import validate_query_platform
from opentide.core.logging import print_banner
from Engines.modules.deployment import DeploymentStrategy, make_deploy_plan


def main() -> None:
    print_banner()
    ctx = CliContext(show_banner=False)
    ctx.apply_environment()
    deployment_plan = DeploymentStrategy.load_from_environment()
    deployment_list = make_deploy_plan(deployment_plan, wide_scope=True, keep_deprecated=False)
    for system in deployment_list:
        validate_query_platform(ctx, system, wide=True)


if __name__ == "__main__":
    main()
