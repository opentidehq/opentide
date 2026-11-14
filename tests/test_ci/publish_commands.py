"""Shell commands that publish (npm, cargo), and whether one is a dry run.

Used by test_workflows.py and tests/test_package/test_layout.py: only the
release train (publish.yml) publishes, and every other publish command in a
workflow is a dry run.
"""

from __future__ import annotations

import re

#: Where a shell command ends: `;`, `&&`, `||`, `&`, a pipe, a subshell or a
#: command substitution, a backtick, or the end of the line.
_COMMAND_END = re.compile(r"&&|\|\||[;&|()`\n]")
#: The words each tool runs as a publish. npm runs every prefix of `publish`
#: from `pu` on and takes options before the command; cargo has no abbreviation.
_PUBLISH_WORDS = {
    "npm": frozenset("publish"[:end] for end in range(2, len("publish") + 1)),
    "cargo": frozenset({"publish"}),
}
#: Any spelling of npm's `dry-run` option (one or two dashes, an abbreviation,
#: `--no-`, a value after `=`). A dry run has the plain `--dry-run` and no other.
_DRY_RUN_OPTION = re.compile(r"^-+(?:no-)*dr", flags=re.IGNORECASE)


def _unquote(word: str) -> str:
    return word.replace('"', "").replace("'", "")


def publishes(script: str) -> list[list[str]]:
    """Each shell command in ``script`` that publishes with npm or cargo, as its
    words from the tool on (each command, not each line; continued lines joined)."""
    found = []
    for command in _COMMAND_END.split(script.replace("\\\n", " ")):
        words = command.split()
        plain = [_unquote(word) for word in words]
        for at, word in enumerate(plain):
            # `npm`, a path to it, or `npm@11.21.1` as npx runs it.
            tool = word.rsplit("/", 1)[-1].split("@", 1)[0]
            if tool in _PUBLISH_WORDS and _PUBLISH_WORDS[tool].intersection(plain[at + 1 :]):
                found.append(words[at:])
                break
    return found


def is_dry_run(command: list[str]) -> bool:
    """A publish with the plain `--dry-run`, not quoted, not `--dry-run false`."""
    if [word for word in command if _DRY_RUN_OPTION.match(word)] != ["--dry-run"]:
        return False
    after = command[command.index("--dry-run") + 1 :]
    return not (after and _unquote(after[0]) == "false")
