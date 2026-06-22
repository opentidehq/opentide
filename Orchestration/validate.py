"""Thin wrapper — delegates to opentide CLI validation service."""

from opentide.cli.context import CliContext
from opentide.cli.services.validation import run_validate
from opentide.core.logging import print_banner


def main() -> None:
    print_banner()
    ctx = CliContext(show_banner=False)
    run_validate(ctx)


if __name__ == "__main__":
    main()
