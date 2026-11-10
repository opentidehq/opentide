"""Fail on prose in docs/ that MDX cannot parse.

opentide.org renders docs/ as MDX, where ``<`` opens a JSX tag and ``{`` an
expression. Outside code, a ``<`` that cannot start a tag (``<=>``, ``a < b``)
or a bare ``{``/``}`` makes the website's docs sync refuse the page, and with it
every docs update. Put such text in backticks, or write ``&lt;`` / ``&#123;``.

Run from the repository root (``scripts/validate-docs.sh`` runs it):

    python3 scripts/build/check_docs_mdx.py [DOCS_DIR]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")
INLINE_CODE = re.compile(r"(`+)(?:(?!\1).)+?\1")
STRAY_LT = re.compile(r"<(?![A-Za-z/!>])")
BRACE = re.compile(r"[{}]")
#: A JSX/HTML tag on one line: its attributes may hold ``{...}`` expressions.
TAG = re.compile(r"</?[A-Za-z][^<>]*>")


def _outside_comments(line: str, in_comment: bool) -> tuple[str, bool]:
    """*line* without its ``<!-- ... -->`` parts, and whether a comment is still open after it."""
    kept: list[str] = []
    rest = line
    while True:
        if in_comment:
            end = rest.find("-->")
            if end < 0:
                return "".join(kept), True
            rest, in_comment = rest[end + 3 :], False
        start = rest.find("<!--")
        if start < 0:
            kept.append(rest)
            return "".join(kept), False
        kept.append(rest[:start])
        rest, in_comment = rest[start + 4 :], True


def problems(text: str) -> list[tuple[int, str]]:
    """``(line number, message)`` for each MDX-breaking character outside code."""
    found: list[tuple[int, str]] = []
    fence: str | None = None
    in_comment = False
    in_frontmatter = text.startswith("---\n")
    for number, line in enumerate(text.splitlines(), start=1):
        if in_frontmatter:
            if number > 1 and line.strip() == "---":
                in_frontmatter = False
            continue
        marker = (match := FENCE.match(line)) and match.group(1)
        if fence:
            if marker and marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            continue
        if marker:
            fence = marker
            continue
        uncommented, in_comment = _outside_comments(line, in_comment)
        prose = INLINE_CODE.sub("", uncommented)
        for match in STRAY_LT.finditer(prose):
            found.append((number, f"bare '<' at {prose[match.start() : match.start() + 6]!r}"))
        for match in BRACE.finditer(TAG.sub("", prose)):
            found.append((number, f"bare {match.group()!r}"))
    return found


def main(argv: list[str]) -> int:
    docs = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parents[2] / "docs"
    errors = 0
    for path in sorted(docs.rglob("*.md")):
        for number, message in problems(path.read_text(encoding="utf-8")):
            print(
                f"{path}:{number}: {message}: MDX cannot parse it; use backticks or &lt; / &#123;",
                file=sys.stderr,
            )
            errors += 1
    if errors:
        print(f"check_docs_mdx: {errors} error(s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
