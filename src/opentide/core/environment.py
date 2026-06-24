import os
from importlib import import_module
from typing import Any

from opentide.core.logging import log
from opentide.core.runtime import is_debug as runtime_is_debug


class DebugHelpers:

    @staticmethod
    def is_debug() -> bool:
        """
        Provides an interface to discover whether the current execution
        context is considered to be in a debugging scenario.
        """
        return runtime_is_debug()

    @staticmethod
    def fetch_config_envvar(config_secrets: dict[str, str]) -> dict[str, Any]:
        """Resolve and replace environment-variable placeholders in a config mapping.

        Many configuration files in TIDE use strings that begin with ``$`` to indicate
        that the real value should be read from an environment variable. This
        function walks the provided mapping and replaces any such placeholders
        with the corresponding environment value. It also prints debug guidance
        when running in debug mode and logs missing values.

        Args:
            config_secrets: A mapping of configuration keys to values. Values that
                are strings beginning with ``$`` will be treated as environment
                variable references and replaced with the variable's value.

        Returns:
            The same mapping (mutated in place) with placeholders replaced by
            environment values where applicable.

        Notes:
            - If a referenced environment variable is missing and the runtime is
              not in debug mode, a fatal log entry will be emitted and the
              function will mark that an environment variable error occurred.
            - When running in debug mode, a local helper module
              ``opentide.core.local_secrets`` is imported (if present) to help
              set environment variables for local development.
        """
        missing_envvar_error = False
        if DebugHelpers.is_debug():
            try:
                import_module("opentide.core.local_secrets")
            except ImportError:
                log(
                    "FAILURE",
                    "Could not find local python file at "
                    "`opentide.core.local_secrets` to set secret environment variables",
                    "Parts of this module may not work properly",
                    "Refer to the relevant TOML configuration file to find which "
                    "variables may be necessary",
                )
        for sec in config_secrets.copy():
            if not config_secrets[sec]:
                log(
                    "SKIP",
                    "Did not find an entry for",
                    sec,
                    "If there are deployment issues, review if it is relevant to configure",
                )
                continue
            value = config_secrets[sec]
            if isinstance(value, str) and value.startswith("$"):
                env_name = value.removeprefix("$")
                if env_name in os.environ:
                    config_secrets[sec] = os.environ.get(env_name, "")
                    log("SUCCESS", "Fetched environment secret", env_name)
                elif DebugHelpers.is_debug():
                    log(
                        "SKIP",
                        "Could not find expected environment variable",
                        value,
                        "Debug Mode identified, continuing - remember that this may "
                        "break some deployments",
                    )
                else:
                    log(
                        "FATAL",
                        "Could not find expected environment variable",
                        value,
                        "Review configuration file and execution environment",
                    )
                    missing_envvar_error = True
        if missing_envvar_error:
            log(
                "FATAL",
                "Some environment variables specified in configuration files were not "
                "found. Review the previous errors to find which ones were missing",
                "Check your CI settings to ensure these environment variables are "
                "properly injected",
                "This may not be a critical issue, for example if you didn't enable a "
                "particular system",
            )
        return config_secrets


HelperTide = DebugHelpers
