"""The rule files the oracle (the frozen Python CLI) reads as changed.

Run by `cargo xtask payloads git --against python` with the oracle's
interpreter, isolated (`python -I git_probe.py REPO RESULT`), once per state of
a scripted git history, outside CI (the last commit against its first parent).
Writes {"files": [names], "nested": [paths]} for the rule files
`modified_rule_scope` reads, or {"error": message} as deploy reports it.

Standard library and the oracle only; no output on stdout is relied on.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys


def main() -> int:
    repo, result_path = sys.argv[1], sys.argv[2]
    os.chdir(repo)
    os.environ["OPENTIDE_REPO_ROOT"] = repo

    from opentide.deployment.git_repo import (
        MissingGitCheckout,
        diff_error_message,
        missing_checkout_message,
        modified_rule_scope,
    )

    result: dict[str, object]
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        try:
            scope = modified_rule_scope()
        except MissingGitCheckout as exc:
            result = {"error": missing_checkout_message(exc.searched)}
        except Exception as exc:  # deploy reports every other failure by its message
            result = {"error": diff_error_message(exc, "selecting the rules to deploy")}
        else:
            result = {
                "files": sorted(path.name for path in scope.files),
                "nested": list(scope.nested),
            }
    with open(result_path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
