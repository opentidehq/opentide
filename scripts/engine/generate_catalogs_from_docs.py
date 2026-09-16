#!/usr/bin/env python3
"""Generate machine-readable catalogs from docs/kql and docs/spl inventories."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def extract_backtick_names(cell: str) -> list[str]:
    names = re.findall(r"`([^`]+)`", cell)
    out: list[str] = []
    for name in names:
        name = name.strip()
        if not name or name in {"—", "-", "...", "…"}:
            continue
        if any(ch in name for ch in "()[]{}…*"):
            continue
        if not re.fullmatch(r"[A-Za-z_!][A-Za-z0-9_.!~-]*", name) and name not in {
            "matches regex",
            "==",
            "!=",
            "=~",
            "!~",
            "<>",
            "<=",
            ">=",
            "<",
            ">",
            "+",
            "-",
            "*",
            "/",
            "%",
            "in~",
            "!in",
        }:
            continue
        out.append(name)
    return out


def parse_md_tables(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    lines = path.read_text().splitlines()
    headers: list[str] | None = None
    for line in lines:
        if not line.startswith("|"):
            headers = None
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if all(set(c) <= set("-: ") and c for c in cells):
            continue
        if headers is None:
            headers = [h.lower() for h in cells]
            continue
        rec = {headers[i]: cells[i] if i < len(cells) else "" for i in range(len(headers))}
        rows.append(rec)
    return rows


def clean_docs(s: str) -> str:
    s = re.sub(r"`+", "", s)
    s = s.replace("\\", "")
    s = re.sub(r"\s+", " ", s).strip()
    # Keep a single sentence for catalog hover; inventories hold the rest.
    if ". " in s:
        s = s.split(". ", 1)[0] + "."
    return s[:240]


def toml_escape(s: str) -> str:
    return s.replace("\\", "").replace('"', '\\"')


def first_name(cell: str) -> str | None:
    names = extract_backtick_names(cell)
    return names[0] if names else None


def write_kql_operators() -> None:
    rows = parse_md_tables(ROOT / "docs/kql/operators.md")
    seen: set[str] = set()
    chunks = [
        "# KQL tabular operators. Generated from docs/kql/operators.md — edit the inventory, then re-run",
        "# scripts/generate_catalogs_from_docs.py",
        "",
    ]
    for row in rows:
        name_cell = row.get("name") or row.get("operator") or ""
        name = first_name(name_cell)
        if not name or name in seen:
            continue
        if name.startswith("."):
            continue
        seen.add(name)
        aliases = extract_backtick_names(row.get("aliases") or "")
        docs = re.sub(r"`+", "", (row.get("short docs") or row.get("docs") or "").strip())
        citation = ""
        cit_cell = row.get("citation") or ""
        m = re.search(r"\((https://[^)]+)\)", cit_cell)
        if m:
            citation = m.group(1)
        detections = (row.get("detections") or "").lower()
        warning = None
        if "nrt-no" in detections and name in {"join", "union", "externaldata"}:
            warning = "nrt_unsupported"
        if name == "render" or "**no**" in detections.replace(" ", ""):
            if name == "render" or name == "consume":
                warning = "not_valid_in_detections"
        if "search *" in detections or name == "search":
            if name == "search":
                warning = "sentinel_star_restricted"
        chunks.append("[[operators]]")
        chunks.append(f'name = "{name}"')
        chunks.append('kind = "tabular"')
        if docs:
            chunks.append(f'docs = "{toml_escape(clean_docs(docs))}"')
        if citation:
            chunks.append(f'citation = "{toml_escape(citation)}"')
        if warning:
            chunks.append(f'warning = "{warning}"')
        chunks.append("")
        for alias in aliases:
            if alias in seen or alias == "—":
                continue
            seen.add(alias)
            chunks.append("[[operators]]")
            chunks.append(f'name = "{alias}"')
            chunks.append('kind = "tabular"')
            chunks.append(f'docs = "Alias of {name}."')
            chunks.append(f'alias_of = "{name}"')
            chunks.append("")
    (ROOT / "catalogs/kql/core/operators.toml").write_text("\n".join(chunks).rstrip() + "\n")
    print(f"kql operators: {len(seen)}")


def write_kql_functions() -> None:
    seen: set[str] = set()
    chunks = [
        "# KQL functions. Generated from docs/kql/scalar-functions.md and aggregation-functions.md",
        "",
    ]

    def add(name: str, signature: str, docs: str, citation: str, kind: str) -> None:
        if name in seen:
            return
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            return
        seen.add(name)
        chunks.append("[[functions]]")
        chunks.append(f'name = "{name}"')
        if signature:
            chunks.append(f'signature = "{toml_escape(signature)}"')
        if docs:
            chunks.append(f'docs = "{toml_escape(clean_docs(docs))}"')
        if citation:
            chunks.append(f'citation = "{toml_escape(citation)}"')
        if kind:
            chunks.append(f'kind = "{kind}"')
        chunks.append("")

    for path, kind in [
        (ROOT / "docs/kql/scalar-functions.md", "scalar"),
        (ROOT / "docs/kql/aggregation-functions.md", "aggregate"),
    ]:
        for row in parse_md_tables(path):
            name_cell = row.get("name") or row.get("function") or ""
            names = extract_backtick_names(name_cell)
            if not names:
                continue
            aliases = extract_backtick_names(row.get("aliases") or "")
            signature = (row.get("signature") or "").replace("`", "")
            docs = re.sub(r"`+", "", (row.get("docs") or "").strip())
            citation = ""
            m = re.search(r"\((https://[^)]+)\)", row.get("citation") or "")
            if m:
                citation = m.group(1)
            for n in names + aliases:
                if "(" in n:
                    n = n.split("(")[0]
                add(n, signature, docs, citation, kind)

    (ROOT / "catalogs/kql/core/functions.toml").write_text("\n".join(chunks).rstrip() + "\n")
    print(f"kql functions: {len(seen)}")


def write_kql_scalar_ops() -> None:
    rows = parse_md_tables(ROOT / "docs/kql/operators-scalar.md")
    chunks = ["# KQL scalar/comparison operators. Generated from docs/kql/operators-scalar.md", ""]
    seen: set[str] = set()
    for row in rows:
        name_cell = row.get("name") or row.get("operator") or row.get("token") or ""
        names = extract_backtick_names(name_cell)
        if not names:
            # Some tables use the operator as bare first column
            first = (name_cell or next(iter(row.values()), "")).strip().strip("`")
            if first:
                names = [first]
        docs = re.sub(r"`+", "", (row.get("docs") or row.get("short docs") or "").strip())
        citation = ""
        m = re.search(r"\((https://[^)]+)\)", row.get("citation") or "")
        if m:
            citation = m.group(1)
        for name in names:
            if name in seen or len(name) > 32:
                continue
            if " " in name and name != "matches regex":
                continue
            seen.add(name)
            chunks.append("[[scalar_operators]]")
            chunks.append(f'name = "{toml_escape(name)}"')
            if docs:
                chunks.append(f'docs = "{toml_escape(clean_docs(docs))}"')
            if citation:
                chunks.append(f'citation = "{toml_escape(citation)}"')
            chunks.append("")
    (ROOT / "catalogs/kql/core/operators-scalar.toml").write_text("\n".join(chunks).rstrip() + "\n")
    print(f"kql scalar operators: {len(seen)}")


def write_tables(src: Path, dest: Path, profile: str) -> None:
    chunks = [f"# {profile} tables. Generated from {src.relative_to(ROOT)}", ""]
    seen: set[str] = set()
    for row in parse_md_tables(src):
        name_cell = row.get("name") or row.get("table") or ""
        names = extract_backtick_names(name_cell)
        docs = re.sub(r"`+", "", (row.get("docs") or row.get("short docs") or next(
            (v for k, v in row.items() if "description" in k or "purpose" in k), ""
        )).strip())
        citation = ""
        m = re.search(r"\((https://[^)]+)\)", " ".join(row.values()))
        if m:
            citation = m.group(1)
        category = None
        for n in names:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", n):
                continue
            if n in seen:
                continue
            seen.add(n)
            chunks.append("[[tables]]")
            chunks.append(f'name = "{n}"')
            chunks.append(f'profile = "{profile}"')
            if docs:
                chunks.append(f'docs = "{toml_escape(clean_docs(docs))}"')
            if citation:
                chunks.append(f'citation = "{toml_escape(citation)}"')
            if n.startswith("Device"):
                chunks.append('category = "endpoint"')
            elif n.startswith("Email") or n.startswith("Identity") or n.startswith("CloudApp"):
                chunks.append('category = "xdr"')
            chunks.append("")
    dest.write_text("\n".join(chunks).rstrip() + "\n")
    print(f"{profile} tables: {len(seen)}")


def write_spl() -> None:
    cmd_rows = parse_md_tables(ROOT / "docs/spl/commands.md")
    eval_rows = parse_md_tables(ROOT / "docs/spl/eval-functions.md")
    stats_rows = parse_md_tables(ROOT / "docs/spl/stats-functions.md")
    chunks = [
        "# Splunk search commands and functions. Generated from docs/spl/ — authored SPL is not rewritten.",
        "",
    ]
    seen: set[str] = set()
    for row in cmd_rows:
        name = first_name(row.get("name") or "")
        if not name or name in seen:
            continue
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            continue
        seen.add(name)
        kind = (row.get("kind") or "streaming").split("(")[0].split(";")[0].strip()
        kind = kind.split("/")[0].strip()
        if kind not in {"generating", "transforming", "streaming", "dataset", "orchestrating"}:
            # Map verbose kinds
            low = (row.get("kind") or "").lower()
            if "generat" in low:
                kind = "generating"
            elif "transform" in low:
                kind = "transforming"
            elif "dataset" in low:
                kind = "dataset"
            elif "orchestr" in low:
                kind = "orchestrating"
            else:
                kind = "streaming"
        docs = re.sub(r"`+", "", (row.get("short docs") or row.get("docs") or "").strip())
        citation = ""
        m = re.search(r"\((https://[^)]+)\)", row.get("citation") or "")
        if m:
            citation = m.group(1)
        chunks.append("[[commands]]")
        chunks.append(f'name = "{name}"')
        chunks.append(f'kind = "{kind}"')
        if docs:
            chunks.append(f'docs = "{toml_escape(clean_docs(docs))}"')
        if citation:
            chunks.append(f'citation = "{toml_escape(citation)}"')
        chunks.append("")
    print(f"spl commands: {len(seen)}")

    fn_seen: set[str] = set()
    for rows, kind in [(eval_rows, "eval"), (stats_rows, "aggregate")]:
        for row in rows:
            name_cell = row.get("name") or row.get("function") or ""
            names = extract_backtick_names(name_cell)
            docs = re.sub(r"`+", "", (row.get("docs") or row.get("short docs") or "").strip())
            for n in names:
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", n) or n in fn_seen:
                    continue
                fn_seen.add(n)
                chunks.append("[[functions]]")
                chunks.append(f'name = "{n}"')
                chunks.append(f'kind = "{kind}"')
                if docs:
                    chunks.append(f'docs = "{toml_escape(clean_docs(docs))}"')
                chunks.append("")
    print(f"spl functions: {len(fn_seen)}")
    (ROOT / "catalogs/spl/commands.toml").write_text("\n".join(chunks).rstrip() + "\n")


def write_types() -> None:
    (ROOT / "catalogs/kql/core/types.toml").write_text(
        """# KQL scalar types. Generated from docs/kql/types.md

[[types]]
name = "bool"

[[types]]
name = "datetime"

[[types]]
name = "decimal"

[[types]]
name = "dynamic"

[[types]]
name = "guid"

[[types]]
name = "int"

[[types]]
name = "long"

[[types]]
name = "real"

[[types]]
name = "string"

[[types]]
name = "timespan"
"""
    )


def main() -> None:
    write_kql_operators()
    write_kql_functions()
    write_kql_scalar_ops()
    write_tables(
        ROOT / "docs/kql/sentinel-tables.md",
        ROOT / "catalogs/kql/sentinel/tables.toml",
        "sentinel",
    )
    write_tables(
        ROOT / "docs/kql/defender-tables.md",
        ROOT / "catalogs/kql/defender/tables.toml",
        "defender",
    )
    write_spl()
    write_types()


if __name__ == "__main__":
    main()
