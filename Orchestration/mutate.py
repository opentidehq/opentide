"""Thin wrapper — delegates to opentide CLI mutate service."""

from opentide.cli.context import CliContext
from opentide.cli.services.mutate import run_mutate
from opentide.core.logging import print_banner


def main() -> None:
    print_banner()
    ctx = CliContext(show_banner=False)
    run_mutate(ctx)


if __name__ == "__main__":
    main()
