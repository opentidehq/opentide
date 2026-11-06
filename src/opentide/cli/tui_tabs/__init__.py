"""The tabs of ``opentide tui`` beyond the catalogue, each in its own module.

Like :mod:`opentide.cli.tui_app`, they import Textual, so only that module
imports them, when the UI opens. What they show comes from
:mod:`opentide.cli.services`, the same functions the commands use.
"""
