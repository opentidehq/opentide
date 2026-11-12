"""Which implementation runs a command when ``OPENTIDE_ENGINE`` is unset (plan §7, #822).

The rollout of a command's Rust implementation, one command at a time:

1. It runs Python by default, and ``OPENTIDE_ENGINE=compare`` (CI's golden
   comparison, and users who opt in) runs both for one release.
2. With zero differences for that release, its default flips here to
   ``rust``, with a changelog entry. ``OPENTIDE_ENGINE=python`` still runs
   the Python implementation for one more release: the escape hatch.
3. The release after, the Python implementation is deleted.

A command flips only when it is in :data:`opentide.cli.engines.RUST_COMMANDS`
(the CLI), or, for the SDK and MCP surfaces that return its result
(``run_validation``, ``validation_report``), when the library has its Rust
implementation. No command has flipped yet.

One kind of run goes to Rust whatever the defaults say: a platform plugin's,
since only the Rust core has the plugin hook (#835). That is a ``query``,
``validate query`` or ``deploy`` on an installed plugin's platform (UC-4.5b),
and a ``validate`` of a workspace that enables one (UC-4.5c), whose blocks
only the Rust core checks. The root callback reads :func:`names_other_platform`
and :func:`may_check_plugins` to know whether a run may be one;
:func:`opentide.cli.engines.plugin_default` decides.

Standard library only, and no imports at all: the root callback reads it on
every run. :func:`enabled_other_platforms` imports a TOML parser only for a
workspace with a platform file outside the built-in ones.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

#: The variable that chooses the implementation for every command at once.
ENGINE_ENV = "OPENTIDE_ENGINE"
PYTHON = "python"
RUST = "rust"

#: A command path's default engine when ``OPENTIDE_ENGINE`` is unset or blank;
#: a path that is not here runs Python. Only ``python`` or ``rust``.
DEFAULT_ENGINES: dict[tuple[str, ...], str] = {}

#: The built-in platforms (``opentide.plugins.BUILTIN_PLATFORMS``, kept here
#: so the console script imports nothing more): any other ``--platform`` may
#: be a platform plugin's.
BUILTIN_PLATFORMS: frozenset[str] = frozenset(
    {
        "carbon_black_cloud",
        "crowdstrike",
        "defender_for_endpoint",
        "elastic",
        "harfanglab",
        "sentinel",
        "sentinel_one",
        "splunk",
        "sysdig",
    }
)


def platform_values(options: Sequence[str]) -> list[str]:
    """The values of every ``--platform`` in *options* (``--platform x`` and ``--platform=x``)."""
    values: list[str] = []
    for index, token in enumerate(options):
        if token == "--platform" and index + 1 < len(options):
            values.append(options[index + 1])
        elif token.startswith("--platform="):
            values.append(token.partition("=")[2])
    return values


def names_other_platform(args: Sequence[str]) -> bool:
    """Whether *args* name a ``--platform`` that is not built in, before any ``--``.

    Such a run may be a platform plugin's, which the default engine hands to
    Rust (:func:`opentide.cli.engines.plugin_default`). Reads the arguments
    alone: no entry point is looked up.
    """
    options = args[: args.index("--")] if "--" in args else args
    return any(name not in BUILTIN_PLATFORMS for name in platform_values(options))


#: The commands the default engine runs on Rust when the run's workspace
#: enables an installed platform plugin's platform (UC-4.5c, #835):
#: ``validate`` checks the plugin's blocks of each rule with the plugin's own
#: model, which the Python implementation reports as extra keys.
PLUGIN_WORKSPACE_COMMANDS: frozenset[tuple[str, ...]] = frozenset({("validate",)})

#: Where a workspace's platform files are, under its root.
PLATFORM_FILES = (".opentide", "configurations", "platforms")


def may_check_plugins(words: Sequence[str], args: Sequence[str], env: Mapping[str, str]) -> bool:
    """Whether a run whose leading words are *words* may be a plugin workspace's ``validate``.

    The root callback's cheap test before it loads the dispatcher, which
    decides (:func:`opentide.cli.engines.plugin_default`): the command is
    ``validate`` (not ``validate query``) and the workspace enables a platform
    outside the built-in ones (:func:`enabled_other_platforms`). No entry
    point is looked up.
    """
    return (
        tuple(words[:1]) == ("validate",)
        and tuple(words[1:2]) != ("query",)
        and bool(enabled_other_platforms(args, env))
    )


def run_workspace(args: Sequence[str], env: Mapping[str, str], cwd: str | None = None) -> str:
    """The workspace a run of *args* opens, as the root callback places it.

    ``--repo``, else ``OPENTIDE_TIDE_WORKSPACE``, else ``OPENTIDE_REPO_ROOT``,
    else the nearest workspace root above *cwd* (the process's when
    ``None``), as :func:`opentide.core.root.find_workspace_root` finds it.
    Relative paths are read from *cwd*. Reads the file system with
    :mod:`os.path` alone.
    """
    import os

    base = os.getcwd() if cwd is None else cwd
    options = args[: args.index("--")] if "--" in args else args
    repo = None
    for index, token in enumerate(options):
        if token == "--repo" and index + 1 < len(options):
            repo = options[index + 1]
        elif token.startswith("--repo="):
            repo = token.partition("=")[2]
    explicit = bool(repo)
    if not explicit:
        repo = env.get("OPENTIDE_REPO_ROOT") or None
    workspace = env.get("OPENTIDE_TIDE_WORKSPACE") if not explicit else None
    chosen = workspace or repo
    if chosen:
        return os.path.join(base, chosen)
    return _workspace_root(base)


def _workspace_root(start: str) -> str:
    """:func:`opentide.core.root.find_workspace_root` with :mod:`os.path` alone."""
    import os

    path = os.path.realpath(start)
    ancestors = [path]
    while os.path.dirname(ancestors[-1]) != ancestors[-1]:
        ancestors.append(os.path.dirname(ancestors[-1]))
    git = next(
        (
            folder
            for folder in ancestors
            if os.path.isdir(os.path.join(folder, ".git"))
            or os.path.isfile(os.path.join(folder, ".git"))
        ),
        None,
    )
    for folder in ancestors:
        if ".git" not in folder.split(os.sep) and (
            os.path.isdir(os.path.join(folder, ".opentide"))
            or (
                os.path.isdir(os.path.join(folder, "objects"))
                and not os.path.isfile(os.path.join(folder, "objects", "__init__.py"))
            )
        ):
            return folder
        if folder == git:
            break
    return git or path


def enabled_other_platforms(
    args: Sequence[str], env: Mapping[str, str], cwd: str | None = None
) -> list[str]:
    """The platforms the run's workspace enables that are not built in, sorted.

    Each is a platform file, ``.opentide/configurations/platforms/<id>.toml``
    of :func:`run_workspace`, whose ``[platform]`` table has ``enabled =
    true``. A workspace with no platform file outside the built-in ones costs
    one directory listing; a file that cannot be read or parsed counts as not
    enabled (``validate`` reports it). No entry point is looked up: whether a
    plugin provides the platform is :func:`opentide.cli.engines.plugin_default`'s
    question.
    """
    import os

    folder = os.path.join(run_workspace(args, env, cwd), *PLATFORM_FILES)
    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return []
    candidates = [
        name
        for name in names
        if name.endswith(".toml")
        and name[: -len(".toml")] not in BUILTIN_PLATFORMS
        and os.path.isfile(os.path.join(folder, name))
    ]
    if not candidates:
        return []
    import sys

    if sys.version_info >= (3, 11):
        import tomllib
    else:
        import tomli as tomllib

    enabled: list[str] = []
    for name in candidates:
        try:
            with open(os.path.join(folder, name), encoding="utf-8") as handle:
                document = tomllib.loads(handle.read())
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
            continue
        platform = document.get("platform")
        if isinstance(platform, dict) and platform.get("enabled") is True:
            enabled.append(name[: -len(".toml")])
    return enabled


def default_engine(words: tuple[str, ...]) -> str:
    """The engine that runs *words* (a command path) when ``OPENTIDE_ENGINE`` is unset."""
    return DEFAULT_ENGINES.get(tuple(words), PYTHON)


def selected(words: tuple[str, ...], env: Mapping[str, str]) -> str:
    """The engine that runs *words*: ``OPENTIDE_ENGINE`` as written, else the default."""
    return env.get(ENGINE_ENV, "").strip() or default_engine(words)


def any_default(words: tuple[str, ...]) -> bool:
    """Whether a command that starts with *words* defaults to something other than Python.

    The root callback's cheap test before it loads the dispatcher: *words* are
    the command line's leading words, which may run past the command path
    into its arguments.
    """
    return any(
        engine != PYTHON and tuple(words[: len(path)]) == path
        for path, engine in DEFAULT_ENGINES.items()
    )
