#!/usr/bin/env python3
"""Fill KQL function, operator, and plugin signatures from Microsoft Learn sources.

The Learn articles are the markdown published from
MicrosoftDocs/dataexplorer-docs (data-explorer/kusto/query). Pass that
directory with --docs. Rows whose own article cannot be read are left
unchanged and printed as skipped.
"""

from __future__ import annotations

import argparse
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEARN = "https://learn.microsoft.com/kusto/query"

NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
CALL_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def strip_front_matter(text: str) -> str:
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) == 3:
            return parts[2]
    return text


def strip_docfx(text: str) -> str:
    text = re.sub(r":::no-loc text=\"([^\"]*)\":::", r"\1", text)
    text = re.sub(r":::.*?:::", "", text, flags=re.S)
    return text


def md_inline_to_text(text: str) -> str:
    text = strip_docfx(text)
    # Keep literal asterisks written as `\*` or `` `*` `` (wildcard tokens).
    text = text.replace("`*`", "\u0001")
    text = text.replace(r"\*", "\u0001")
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = text.replace("`", "")
    text = re.sub(r"<br\s*/?>", " ", text, flags=re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    text = text.replace("*", "")
    text = text.replace("\u0001", "*")
    text = text.replace("&emsp;", " ")
    text = re.sub(r"\s+", " ", text).strip()
    return text


def first_sentence(text: str) -> str:
    text = text.strip()
    if not text:
        return ""
    match = re.search(r".+?[.!?](?:\s|$)", text)
    sentence = match.group(0).strip() if match else text
    sentence = sentence[:240].rstrip()
    if sentence and sentence[-1] not in ".!?":
        sentence += "."
    return sentence


def section_until(body: str, heading: str) -> str:
    match = re.search(rf"^## {re.escape(heading)}\s*$", body, re.M)
    if not match:
        return ""
    rest = body[match.end() :]
    end = re.search(r"^## ", rest, re.M)
    return rest[: end.start()] if end else rest


def prefer_sentinel(section: str) -> str:
    """Use the Sentinel/Monitor moniker when the article branches syntax."""
    ranges = list(re.finditer(r'::: ?moniker range="([^"]+)"', section))
    if not ranges:
        return section
    chosen: list[str] = []
    for index, match in enumerate(ranges):
        if "microsoft-sentinel" not in match.group(1) and "azure-monitor" not in match.group(1):
            continue
        start = match.end()
        end_match = re.search(r"::: ?moniker-end", section[start:])
        end = start + end_match.start() if end_match else len(section)
        # stop before the next moniker opener if the end marker is missing
        if index + 1 < len(ranges) and ranges[index + 1].start() < end:
            end = ranges[index + 1].start()
        chosen.append(section[start:end])
    if not chosen:
        return section
    # Drop moniker wrappers from the chosen chunks only.
    return "\n".join(chosen)


def clean_syntax_lines(section: str) -> str:
    lines: list[str] = []
    for line in section.splitlines():
        stripped = line.strip()
        if stripped.startswith("[!INCLUDE") or stripped.startswith(":::"):
            continue
        if stripped.startswith(">"):
            continue
        lines.append(line)
    return "\n".join(lines)


def syntax_plain(body: str, name: str | None = None) -> str:
    section = section_until(body, "Syntax")
    if not section:
        section = body
    section = prefer_sentinel(section)
    parts = re.split(r"(?=^### )", section, flags=re.M)
    chosen = None
    if name:
        for part in parts:
            plain = md_inline_to_text(clean_syntax_lines(part))
            if re.search(rf"(?i)(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", plain):
                chosen = plain
                break
    if chosen:
        return chosen
    return md_inline_to_text(clean_syntax_lines(section))


INCLUDE_RE = re.compile(r"\[!INCLUDE \[[^\]]+\]\(([^)]+)\)\]")


def expand_includes(body: str, docs: Path) -> str:
    def repl(match: re.Match[str]) -> str:
        rel = match.group(1)
        candidates = [
            (docs / rel).resolve(),
            (docs.parent / "includes" / Path(rel).name).resolve(),
        ]
        for path in candidates:
            if path.exists():
                text = path.read_text(errors="replace")
                return strip_front_matter(text)
        return ""

    return INCLUDE_RE.sub(repl, body)


def intro_sentence(body: str) -> str:
    head = body.split("## Syntax", 1)[0]
    lines: list[str] = []
    seen_title = False
    for line in head.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            seen_title = True
            continue
        if not seen_title:
            continue
        if (
            not stripped
            or stripped.startswith(">")
            or stripped.startswith("[!")
            or stripped.startswith(":::")
            or stripped.startswith("---")
        ):
            if lines:
                break
            continue
        lines.append(stripped)
    return first_sentence(md_inline_to_text(" ".join(lines)))


def header_aliases(body: str) -> set[str]:
    head = body.split("## Syntax", 1)[0]
    names: set[str] = set()
    cleaned = head.replace("**", "")
    for match in re.finditer(r"(?i)deprecated aliases?\s*:([^\n]+)", cleaned):
        names.update(re.findall(r"([A-Za-z_][A-Za-z0-9_-]*)\s*\(\s*\)", match.group(1)))
    for match in re.finditer(r"(?i)equivalent", head):
        line_start = head.rfind("\n", 0, match.start()) + 1
        line_end = head.find("\n", match.end())
        line = head[line_start : line_end if line_end != -1 else None]
        names.update(re.findall(r"`([A-Za-z_][A-Za-z0-9_-]*)(?:\(\))?\s*`", line))
    for match in re.finditer(r"(?i)`?([A-Za-z_][A-Za-z0-9_-]*)`?\s+is a legacy\b", body):
        names.add(match.group(1))
    return {name for name in names if name.lower() not in {"the", "and", "or", "a", "an"}}


def normalize_signature(signature: str) -> str:
    signature = re.sub(r"\s+", " ", signature).strip()
    signature = re.sub(r"\s*\(\s*", "(", signature)
    signature = re.sub(r"\s*\)", ")", signature)
    signature = re.sub(r"\s*,\s*", ", ", signature)
    signature = re.sub(r"\[\s+", "[", signature)
    signature = re.sub(r"\s+\]", "]", signature)
    signature = re.sub(r"\s*\|\s*", " | ", signature)
    signature = re.sub(r"\s+", " ", signature).strip()
    return signature


def balanced_end(text: str, open_index: int, open_ch: str, close_ch: str) -> int | None:
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == open_ch:
            depth += 1
        elif char == close_ch:
            depth -= 1
            if depth == 0:
                return index
    return None


def extract_call(name: str, plain: str) -> str | None:
    pattern = re.compile(rf"(?i)(?<![A-Za-z0-9_]){re.escape(name)}\s*\(")
    match = pattern.search(plain)
    if not match:
        return None
    open_index = plain.find("(", match.start())
    end = balanced_end(plain, open_index, "(", ")")
    if end is None:
        return None
    signature = plain[match.start() : end + 1]
    # Keep bracket groups that continue the same syntax (`datatable(...) [...]`).
    rest = plain[end + 1 :]
    while True:
        trimmed = rest.lstrip()
        if not trimmed.startswith("["):
            break
        gap = rest[: len(rest) - len(trimmed)]
        if gap.strip():
            break
        bracket_end = balanced_end(trimmed, 0, "[", "]")
        if bracket_end is None:
            break
        signature += trimmed[: bracket_end + 1]
        rest = trimmed[bracket_end + 1 :]
    # Force the catalog's own spelling of the name.
    signature = re.sub(rf"(?i)^{re.escape(name)}", name, signature, count=1)
    return normalize_signature(signature)


def operator_signature(name: str, plain: str) -> str | None:
    found = list(re.finditer(rf"(?i)(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", plain))
    if len(found) >= 2:
        plain = re.sub(r"\s+T\s*\|\s*$", "", plain[: found[1].start()]).strip()
    call = extract_call(name, plain)
    # A bare `name()` is usually an alias mention, not the argument list.
    if call and not re.fullmatch(rf"(?i){re.escape(name)}\(\)", call):
        return call
    match = re.search(rf"(?i)(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", plain)
    if not match:
        return None
    rest = plain[match.end() :].strip()
    rest = re.split(r"\s+or\s+(?=[A-Z*`(\[])", rest, maxsplit=1)[0].strip()
    rest = re.sub(r"\s+", " ", rest).strip(" |")
    if rest in {"", "()"}:
        return f"{name}()"
    return normalize_signature(f"{name}({rest})")


def split_row(line: str) -> list[str]:
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    return [cell.replace(r"\|", "|").strip() for cell in re.split(r"(?<!\\)\|", line)]


def parse_parameters(body: str) -> list[dict[str, object]]:
    section = section_until(body, "Parameters")
    if not section:
        return []
    # The parameters table is the first table; nested headings start more tables.
    rows: list[list[str]] = []
    for line in section.splitlines():
        stripped = line.strip()
        if stripped.startswith("###") or stripped.startswith(">"):
            if rows:
                break
            continue
        if not stripped.startswith("|"):
            if rows:
                break
            continue
        cells = split_row(stripped)
        if cells and all(set(cell) <= set("-: ") and cell for cell in cells):
            continue
        rows.append(cells)
    if len(rows) < 2:
        return []
    header = [md_inline_to_text(cell).lower() for cell in rows[0]]

    def column(*needles: str) -> int | None:
        for needle in needles:
            for index, name in enumerate(header):
                if needle in name:
                    return index
        return None

    name_i = column("name")
    required_i = column("required")
    docs_i = column("description")
    if name_i is None:
        return []
    params: list[dict[str, object]] = []
    for cells in rows[1:]:
        if name_i >= len(cells):
            continue
        raw_name = md_inline_to_text(cells[name_i])
        raw_name = raw_name.replace(" or ", " | ")
        raw_name = re.sub(r"\s+", " ", raw_name).strip(" *")
        if not raw_name or raw_name.lower() in {"name"}:
            continue
        # Piped input is not an argument the author types after the operator.
        if raw_name in {"T", "LeftTable", "Edges", "G"}:
            continue
        required = False
        if required_i is not None and required_i < len(cells):
            required = "heavy_check_mark" in cells[required_i] or "✔️" in cells[required_i]
        docs = ""
        if docs_i is not None and docs_i < len(cells):
            docs = first_sentence(md_inline_to_text(cells[docs_i]))
        params.append({"name": raw_name[:120], "docs": docs, "required": required})
    return params


def citation_for(path: Path) -> str:
    return f"{LEARN}/{path.stem}"


def load_articles(docs: Path) -> list[tuple[Path, str, str]]:
    articles: list[tuple[Path, str, str]] = []
    for path in sorted(docs.glob("*.md")):
        text = path.read_text(errors="replace")
        body = strip_front_matter(text)
        titled = bool(re.search(r"^# .+\(\)\s*$", body, re.M))
        if not (
            path.name.endswith("-function.md")
            or path.name.endswith("-operator.md")
            or path.name.endswith("-plugin.md")
            or titled
        ):
            continue
        body = expand_includes(body, docs)
        articles.append((path, body, syntax_plain(body)))
    return articles


class ArticleIndex:
    def __init__(self, articles: list[tuple[Path, str, str]]) -> None:
        self.by_primary: dict[str, list[tuple[Path, str, str]]] = {}
        self.by_alias: dict[str, list[tuple[Path, str, str]]] = {}
        for path, body, plain in articles:
            primaries = set(CALL_RE.findall(plain))
            if path.name.endswith("-operator.md"):
                primaries.add(path.name[: -len("-operator.md")])
            elif path.name.endswith("-plugin.md"):
                primaries.add(path.name[: -len("-plugin.md")])
            for line in body.splitlines():
                stripped = line.strip()
                if "`" not in stripped or "(" not in stripped or stripped.startswith("```") or stripped.startswith("|"):
                    continue
                primaries.update(CALL_RE.findall(md_inline_to_text(stripped)))
            # Operators are not always written as calls.
            title = ""
            for line in body.splitlines():
                if line.startswith("# "):
                    title = line[2:].strip()
                    break
            title_names = re.findall(r"`?([A-Za-z_][A-Za-z0-9_-]*)`?\s*\(", title)
            for name in primaries | set(title_names):
                key = name.lower()
                self.by_primary.setdefault(key, [])
                if all(existing[0] != path for existing in self.by_primary[key]):
                    self.by_primary[key].append((path, body, plain))
            for alias in header_aliases(body):
                key = alias.lower()
                self.by_alias.setdefault(key, [])
                if all(existing[0] != path for existing in self.by_alias[key]):
                    self.by_alias[key].append((path, body, plain))

    def resolve(self, name: str, citation: str | None) -> tuple[Path, str, str, str] | None:
        key = name.lower()
        primaries = self.by_primary.get(key, [])
        chosen = pick_filename(primaries, name)
        if chosen:
            path, body, plain = chosen
            return path, body, plain, "primary"
        if len(primaries) == 1:
            path, body, plain = primaries[0]
            return path, body, plain, "primary"
        if len(primaries) > 1:
            chosen = pick_citation(primaries, citation)
            if chosen:
                path, body, plain = chosen
                return path, body, plain, "primary"
            return None
        aliases = self.by_alias.get(key, [])
        chosen = pick_filename(aliases, name) or (aliases[0] if len(aliases) == 1 else pick_citation(aliases, citation))
        if chosen:
            path, body, plain = chosen
            return path, body, plain, "alias"
        return None


def pick_citation(
    rows: list[tuple[Path, str, str]], citation: str | None
) -> tuple[Path, str, str] | None:
    if not citation:
        return None
    stem = citation.rstrip("/").split("/")[-1]
    for row in rows:
        if row[0].stem == stem:
            return row
    return None


def article_slug(path: Path) -> str:
    stem = path.stem.lower()
    for suffix in ("-aggregation-function", "-function", "-operator", "-plugin"):
        if stem.endswith(suffix):
            return stem[: -len(suffix)]
    return stem


def pick_filename(
    rows: list[tuple[Path, str, str]], name: str
) -> tuple[Path, str, str] | None:
    kebab = name.replace("_", "-").lower()
    matches = [row for row in rows if article_slug(row[0]) == kebab]
    if len(matches) == 1:
        return matches[0]
    return None


def plain_for(body: str, name: str) -> str:
    plain = syntax_plain(body, name)
    call = extract_call(name, plain)
    if call and not re.fullmatch(rf"(?i){re.escape(name)}\(\)", call):
        return plain
    if re.search(rf"(?i)(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", plain) and "(" not in plain[plain.lower().find(name.lower()) :]:
        # Pipe syntax (`T | where Predicate`) with no call. Keep it.
        if "|" in plain or not call:
            return plain
    variant = None
    if name.startswith("percentile_"):
        variant = "percentiles_" + name[len("percentile_") :]
    target = variant or name
    for line in body.splitlines():
        if target.lower() not in line.lower() or "`" not in line:
            continue
        if line.strip().startswith("```") or line.strip().startswith("|"):
            continue
        plain_line = md_inline_to_text(line)
        found = extract_call(target, plain_line)
        if found and not re.fullmatch(rf"(?i){re.escape(target)}\(\)", found):
            if variant:
                plain_line = re.sub(rf"(?i){re.escape(variant)}", name, plain_line, count=1)
            return plain_line
    return plain


def parameters_for(body: str, name: str) -> list[dict[str, object]]:
    lower = body.lower()
    idx = lower.find(f"`{name.lower()}")
    if idx < 0 and name.startswith("percentile_"):
        variant = "percentiles_" + name[len("percentile_") :]
        idx = lower.find(f"`{variant}")
    if idx >= 0:
        window = body[idx : idx + 5000]
        marker = re.search(r"^### Parameters\s*$", window, re.M)
        if marker:
            params = parse_parameters("## Parameters\n" + window[marker.end() :])
            if params:
                return params
    return parse_parameters(body)


def alias_signature(name: str, plain: str, body: str, path: Path) -> str | None:
    """Rewrite the article's own call, using the name this alias is documented beside."""
    candidates: list[str] = []
    for found in CALL_RE.findall(plain):
        if found.lower() != name.lower() and found not in candidates:
            candidates.append(found)
    for alias in header_aliases(body):
        if alias.lower() != name.lower() and alias not in candidates:
            candidates.append(alias)
    slug = article_slug(path)
    if slug.lower() != name.lower() and slug not in candidates:
        candidates.append(slug)
    best: tuple[str, str] | None = None
    for primary in candidates:
        host = extract_call(primary, plain) or operator_signature(primary, plain)
        if not host or not re.match(rf"(?i){re.escape(primary)}\(", host):
            continue
        if best is None or len(host) > len(best[1]):
            best = (primary, host)
    if not best:
        return None
    primary, host = best
    rewritten = re.sub(rf"(?i)^{re.escape(primary)}", name, host, count=1)
    if name.lower() in rewritten.lower() and "(" in rewritten and ")" in rewritten:
        return rewritten
    return None


def signature_for(name: str, plain: str, role: str) -> str | None:
    call = extract_call(name, plain)
    if call and name.lower() in call.lower() and "(" in call and ")" in call:
        return call
    if role == "alias":
        return None
    return operator_signature(name, plain)


def toml_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def write_functions(path: Path, rows: list[dict], skipped: list[str]) -> None:
    chunks = [
        "# KQL scalar and aggregate functions.",
        "# Signatures and parameter docs are taken from each function's own Microsoft Learn article",
        "# (MicrosoftDocs/dataexplorer-docs data-explorer/kusto/query). Do not regenerate by",
        "# splitting those signatures on '|'.",
        "",
    ]
    for row in rows:
        chunks.append("[[functions]]")
        chunks.append(f'name = "{toml_escape(row["name"])}"')
        if row.get("signature"):
            chunks.append(f'signature = "{toml_escape(row["signature"])}"')
        if row.get("docs"):
            chunks.append(f'docs = "{toml_escape(row["docs"])}"')
        if row.get("citation"):
            chunks.append(f'citation = "{toml_escape(row["citation"])}"')
        if row.get("kind"):
            chunks.append(f'kind = "{toml_escape(row["kind"])}"')
        chunks.append("")
        for param in row.get("parameters") or []:
            chunks.append("[[functions.parameters]]")
            chunks.append(f'name = "{toml_escape(param["name"])}"')
            if param.get("docs"):
                chunks.append(f'docs = "{toml_escape(param["docs"])}"')
            chunks.append(f'required = {"true" if param.get("required") else "false"}')
            chunks.append("")
    if skipped:
        chunks.append("# Skipped (Learn article not resolved):")
        for name in skipped:
            chunks.append(f"# - {name}")
        chunks.append("")
    path.write_text("\n".join(chunks).rstrip() + "\n")


def write_operators(path: Path, rows: list[dict]) -> None:
    chunks = [
        "# KQL tabular operators.",
        "# Signatures are the Learn syntax, wrapped as name(...) so signature help has an argument list.",
        "# Blurbs are the article's opening sentence (pipe characters inside signatures are not split).",
        "",
    ]
    for row in rows:
        chunks.append("[[operators]]")
        chunks.append(f'name = "{toml_escape(row["name"])}"')
        chunks.append(f'kind = "{toml_escape(row.get("kind") or "tabular")}"')
        if row.get("signature"):
            chunks.append(f'signature = "{toml_escape(row["signature"])}"')
        if row.get("docs"):
            chunks.append(f'docs = "{toml_escape(row["docs"])}"')
        if row.get("citation"):
            chunks.append(f'citation = "{toml_escape(row["citation"])}"')
        if row.get("warning"):
            chunks.append(f'warning = "{toml_escape(row["warning"])}"')
        if row.get("alias_of"):
            chunks.append(f'alias_of = "{toml_escape(row["alias_of"])}"')
        chunks.append("")
        for param in row.get("parameters") or []:
            chunks.append("[[operators.parameters]]")
            chunks.append(f'name = "{toml_escape(param["name"])}"')
            if param.get("docs"):
                chunks.append(f'docs = "{toml_escape(param["docs"])}"')
            chunks.append(f'required = {"true" if param.get("required") else "false"}')
            chunks.append("")
    path.write_text("\n".join(chunks).rstrip() + "\n")


def write_plugins(path: Path, rows: list[dict]) -> None:
    chunks = [
        "# KQL evaluate plugins. Invoked as: T | evaluate PluginName(...)",
        "# Signatures come from each plugin's Learn article. Extra ADX-only plugins are not added.",
        "",
    ]
    for row in rows:
        chunks.append("[[plugins]]")
        chunks.append(f'name = "{toml_escape(row["name"])}"')
        if row.get("signature"):
            chunks.append(f'signature = "{toml_escape(row["signature"])}"')
        if row.get("docs"):
            chunks.append(f'docs = "{toml_escape(row["docs"])}"')
        if row.get("citation"):
            chunks.append(f'citation = "{toml_escape(row["citation"])}"')
        if row.get("warning"):
            chunks.append(f'warning = "{toml_escape(row["warning"])}"')
        chunks.append("")
        for param in row.get("parameters") or []:
            chunks.append("[[plugins.parameters]]")
            chunks.append(f'name = "{toml_escape(param["name"])}"')
            if param.get("docs"):
                chunks.append(f'docs = "{toml_escape(param["docs"])}"')
            chunks.append(f'required = {"true" if param.get("required") else "false"}')
            chunks.append("")
    path.write_text("\n".join(chunks).rstrip() + "\n")


def apply_article(
    name: str,
    citation: str | None,
    index: ArticleIndex,
    *,
    operator: bool,
) -> tuple[dict | None, str | None]:
    resolved = index.resolve(name, citation)
    if not resolved:
        return None, "no Learn article"
    path, body, _plain, role = resolved
    syntax = syntax_plain(body, name if role == "primary" else None)
    named = re.search(rf"(?i)(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", syntax or "")
    if role == "primary" and not named:
        role = "alias"
    if role == "alias":
        plain = syntax_plain(body)
        signature = alias_signature(name, plain, body, path)
    else:
        plain = plain_for(body, name)
        signature = operator_signature(name, plain) if (operator or path.name.endswith(("-operator.md", "-plugin.md"))) else None
        if signature is None:
            signature = signature_for(name, plain, "primary")
    if not signature or name.lower() not in signature.lower() or "(" not in signature or ")" not in signature:
        return None, f"unusable syntax in {path.name}"
    params = parameters_for(body, name)
    docs = intro_sentence(body)
    return {
        "signature": signature,
        "docs": docs,
        "citation": citation_for(path),
        "parameters": params,
        "source": path.name,
        "role": role,
    }, None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--docs", type=Path, required=True)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    index = ArticleIndex(load_articles(args.docs))

    functions_path = ROOT / "catalogs/kql/core/functions.toml"
    operators_path = ROOT / "catalogs/kql/core/operators.toml"
    plugins_path = ROOT / "catalogs/kql/core/evaluate-plugins.toml"
    functions = tomllib.loads(functions_path.read_text())["functions"]
    # These catalog names are not on the cited Learn page. The page's aliases are
    # base64_encodestring / base64_decodestring. Do not copy the neighbor signature.
    functions = [row for row in functions if row["name"] not in {"encode_base64", "decode_base64"}]
    for alias in ("base64_encodestring", "base64_decodestring"):
        if not any(row["name"] == alias for row in functions):
            functions.append({"name": alias, "kind": "scalar"})
    operators = tomllib.loads(operators_path.read_text())["operators"]
    plugins = tomllib.loads(plugins_path.read_text())["plugins"]

    skipped: list[str] = []
    repaired = 0
    for row in functions:
        applied, reason = apply_article(row["name"], row.get("citation"), index, operator=False)
        if not applied:
            skipped.append(f'{row["name"]}: {reason}')
            continue
        row["signature"] = applied["signature"]
        if applied["docs"]:
            row["docs"] = applied["docs"]
        row["citation"] = applied["citation"]
        row["parameters"] = applied["parameters"]
        repaired += 1

    # column_names_of is the Sentinel helper project-by-names calls. It was absent.
    if not any(row["name"] == "column_names_of" for row in functions):
        applied, reason = apply_article("column_names_of", None, index, operator=False)
        if applied:
            functions.append(
                {
                    "name": "column_names_of",
                    "signature": applied["signature"],
                    "docs": applied["docs"],
                    "citation": applied["citation"],
                    "kind": "scalar",
                    "parameters": applied["parameters"],
                }
            )
            repaired += 1
        else:
            skipped.append(f"column_names_of: {reason}")

    op_skipped: list[str] = []
    for row in operators:
        applied, reason = apply_article(row["name"], row.get("citation"), index, operator=True)
        if not applied:
            op_skipped.append(f'{row["name"]}: {reason}')
            continue
        row["signature"] = applied["signature"]
        if row.get("alias_of"):
            row["docs"] = row.get("docs") or f'Alias of {row["alias_of"]}.'
        elif applied["docs"]:
            row["docs"] = applied["docs"]
        row["citation"] = applied["citation"]
        row["parameters"] = applied["parameters"]

    if not any(row["name"] == "project-by-names" for row in operators):
        applied, reason = apply_article("project-by-names", None, index, operator=True)
        if applied:
            operators.append(
                {
                    "name": "project-by-names",
                    "kind": "tabular",
                    "signature": applied["signature"],
                    "docs": applied["docs"],
                    "citation": applied["citation"],
                    "parameters": applied["parameters"],
                }
            )
        else:
            op_skipped.append(f"project-by-names: {reason}")

    plugin_skipped: list[str] = []
    for row in plugins:
        applied, reason = apply_article(row["name"], row.get("citation"), index, operator=False)
        if not applied:
            plugin_skipped.append(f'{row["name"]}: {reason}')
            continue
        row["signature"] = applied["signature"]
        if applied["docs"]:
            row["docs"] = applied["docs"]
        row["citation"] = applied["citation"]
        row["parameters"] = applied["parameters"]

    print(f"functions repaired {repaired} skipped {len(skipped)}")
    for line in skipped:
        print("  SKIP", line)
    print(f"operators skipped {len(op_skipped)}")
    for line in op_skipped:
        print("  SKIP", line)
    print(f"plugins skipped {len(plugin_skipped)}")
    for line in plugin_skipped:
        print("  SKIP", line)

    interesting = [
        "arg_max",
        "parse_json",
        "todynamic",
        "set_intersect",
        "set_difference",
        "sqrt",
        "exp",
        "log2",
        "log10",
        "gamma",
        "isfinite",
        "isinf",
        "indexof_regex",
        "url_decode",
        "trim_start",
        "trim_end",
        "endofday",
        "ipv6_is_in_range",
        "series_abs",
        "toboolean",
        "column_names_of",
        "replace",
    ]
    by_name = {row["name"]: row for row in functions}
    for name in interesting:
        row = by_name.get(name)
        if not row:
            print(f"MISSING {name}")
            continue
        print(f"{name}: {row.get('signature')} || {row.get('docs')}")

    print("--- suspicious functions ---")
    for row in functions:
        sig = row.get("signature") or ""
        if row["name"].lower() not in sig.lower() or "(" not in sig or ")" not in sig or sig.endswith("()"):
            print(f"  {row['name']}: {sig}")
    print("--- suspicious operators ---")
    for row in operators:
        sig = row.get("signature") or ""
        if row["name"].lower() not in sig.lower() or "(" not in sig or ")" not in sig:
            print(f"  {row['name']}: {sig}")
    print("--- plugins ---")
    for row in plugins:
        sig = row.get("signature") or ""
        if row["name"].lower() not in sig.lower() or "(" not in sig or ")" not in sig:
            print(f"  {row['name']}: {sig}")
        else:
            print(f"  ok {row['name']}: {sig[:140]}")
    print("--- operators ---")
    for row in operators:
        if row["name"] in {"top", "sort", "lookup", "parse", "invoke", "join", "where", "project-by-names", "render", "make-series", "filter", "mvexpand"}:
            print(f"{row['name']}: {row.get('signature')} || {row.get('docs')}")

    if args.write:
        write_functions(functions_path, functions, [line.split(":")[0] for line in skipped])
        write_operators(operators_path, operators)
        write_plugins(plugins_path, plugins)
        print("wrote catalogs")


if __name__ == "__main__":
    main()
