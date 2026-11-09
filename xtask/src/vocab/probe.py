"""What the oracle (the frozen Python CLI) makes of vocabulary values.

Run by `cargo xtask vocab diff --against python` with the oracle's interpreter,
isolated (`python -I probe.py REQUEST RESULT`), once per fixture workspace.
REQUEST is JSON: {"repo": DIR, "selectors": [{"vocab", "scoped", "stages",
"values"}]}. The probe:

1. runs `opentide --json --repo DIR validate` in this process, recording every
   value the vocabulary check resolves (`RuntimeEnumResolver.is_valid`), with
   the field's vocabulary, stages and scope: every vocabulary value of the
   corpus, as the oracle reads it;
2. for every selector of the request and of the corpus, writes the values the
   oracle accepts (the enum before editor search hints), and for every value
   (the request's and the corpus's) whether it is valid and its suggestion;
3. writes the workspace's object vocabularies (`threat`, `objective`, `rule`),
   which the Rust side has no indexer for yet;
4. writes every `vocab_unknown` finding of that `validate --json` report: its
   vocabulary and value, and its `message` and `help` as the CLI prints them.

Standard library and the oracle only; no output on stdout is relied on.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys


def main() -> int:
    request_path, result_path = sys.argv[1], sys.argv[2]
    with open(request_path, encoding="utf-8") as handle:
        request = json.load(handle)
    repo = request["repo"]

    from opentide.validation import vocab_resolver

    seen: dict[tuple[str, str, bool], list[str]] = {}
    original = vocab_resolver.RuntimeEnumResolver.is_valid

    def is_valid(self, value, vocab, *, stages=None, scoped=False, no_wrap=False):
        key = (vocab, json.dumps(_stages(stages)), bool(scoped))
        values = seen.setdefault(key, [])
        if value not in values:
            values.append(value)
        return original(self, value, vocab, stages=stages, scoped=scoped, no_wrap=no_wrap)

    vocab_resolver.RuntimeEnumResolver.is_valid = is_valid  # type: ignore[method-assign]

    from opentide.cli import main as cli

    sys.argv = ["opentide", "--json", "--repo", repo, "validate"]
    out = io.StringIO()
    exit_code = None
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        try:
            cli()
        except SystemExit as stop:
            exit_code = stop.code
    vocab_resolver.RuntimeEnumResolver.is_valid = original  # type: ignore[method-assign]
    findings = _vocab_unknown(out.getvalue())

    from opentide.core.registry import Opentide
    from opentide.models.object_types import CORE_OBJECT_TYPES

    index = Opentide.Vocabularies.Index
    resolver = vocab_resolver.RuntimeEnumResolver(index)

    selectors: dict[tuple[str, str, bool], list[str]] = {}
    for item in request["selectors"]:
        key = (item["vocab"], json.dumps(_stages(item["stages"])), bool(item["scoped"]))
        selectors.setdefault(key, []).extend(item["values"])
    corpus = []
    for key, values in seen.items():
        corpus.append(
            {"vocab": key[0], "stages": json.loads(key[1]), "scoped": key[2], "values": values}
        )
        selectors.setdefault(key, []).extend(values)

    results = []
    for (vocab, stages_json, scoped), values in selectors.items():
        stages = json.loads(stages_json)
        builder = vocab_resolver._VocabEnumBuilder(
            vocab,
            index,
            object_types=CORE_OBJECT_TYPES,
            icons={},
            stages=stages,
            scoped=scoped,
        )
        builder._ingest(index.get(builder._field_name))
        allowed = [value for value in builder.enum if value]
        checked = []
        for value in dict.fromkeys(values):
            valid = resolver.is_valid(value, vocab, stages=stages, scoped=scoped)
            suggestion = (
                None if valid else resolver.suggest(value, vocab, stages=stages, scoped=scoped)
            )
            checked.append([value, valid, suggestion])
        results.append(
            {
                "vocab": vocab,
                "stages": stages,
                "scoped": scoped,
                "allowed": allowed,
                "checked": checked,
            }
        )

    models = {}
    for field in CORE_OBJECT_TYPES:
        definition = index.get(field)
        if definition is None:
            continue
        models[field] = {
            "name": definition.metadata.name,
            "entries": [
                {
                    "key": key,
                    "name": entry.name,
                    "version": entry.version,
                    "removed": entry.removed,
                    "stages": list(entry.stages),
                }
                for key, entry in definition.entries.items()
            ],
        }

    with open(result_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "exit_code": exit_code,
                "corpus": corpus,
                "results": results,
                "models": models,
                "findings": findings,
            },
            handle,
        )
    return 0


def _vocab_unknown(report: str) -> list[dict[str, object]]:
    """Every `vocab_unknown` finding of a `--json` report, once each, in order."""
    try:
        document = json.loads(report)
    except ValueError:
        return []
    found: list[dict[str, object]] = []
    stack = [document]
    while stack:
        node = stack.pop(0)
        if isinstance(node, list):
            stack[:0] = node
            continue
        if not isinstance(node, dict):
            continue
        context = node.get("context")
        if node.get("code") == "vocab_unknown" and "message" in node and isinstance(context, dict):
            finding = {
                "vocab": context.get("vocab"),
                "value": context.get("value"),
                "message": node.get("message"),
                "help": node.get("help"),
            }
            if finding not in found:
                found.append(finding)
            continue
        stack[:0] = list(node.values())
    return found


def _stages(stages: object) -> list[str] | None:
    if stages is None:
        return None
    if isinstance(stages, str):
        return [stages]
    return [str(stage) for stage in stages]  # type: ignore[union-attr]


if __name__ == "__main__":
    raise SystemExit(main())
