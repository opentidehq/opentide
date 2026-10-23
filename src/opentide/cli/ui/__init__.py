"""Presentation for the opentide CLI: the output contract in code.

``mode``      who is reading (``human``, ``plain``, ``agent``, ``json``, ``mcp``)
``glyphs``    status glyphs by name, with ASCII fallbacks
``contract``  ``Failure``, ``NextAction``, usage-error codes, ``did_you_mean``
``render``    outcome, warning, error and next-step lines
``crash``     ``error[internal]``, the redacted crash log and the issue link

``docs/internal/cli-experience.md`` is the specification. Submodules are not
imported here, so asking for the mode never loads Rich.
"""
