"""Thin wrapper — delegates to opentide CLI document service."""

from opentide.cli.context import CliContext
from opentide.cli.services.document import run_document
from opentide.core.logging import print_banner


def main() -> None:
    print_banner()
    ctx = CliContext(show_banner=False)
    run_document(ctx)


if __name__ == "__main__":
    main()
