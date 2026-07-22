"""GitLab markdown formatter."""

from __future__ import annotations

import json
from dataclasses import dataclass

from opentide.documentation.format.protocol import BaseFormatter


@dataclass(frozen=True)
class GitLabFormatter(BaseFormatter):
    """Formatter for GitLab markdown rendering."""

    flavor: str = "gitlab"

    def strike(self, text: str) -> str:
        return f"[-{text}-]"

    def wiki_link(self, text: str, target: str) -> str:
        page = target.removesuffix(".md")
        return self.link(text, page)

    def index_table(self, headers: list[str], rows: list[list[str]]) -> str:
        char = "a"
        key_by_header: dict[str, str] = {}
        for header in headers:
            key_by_header[header] = char
            char = chr(ord(char) + 1)
        fields = [
            {"key": key_by_header[header], "label": header, "sortable": "true"}
            for header in headers
        ]
        items = [
            {key_by_header[header]: cell for header, cell in zip(headers, row, strict=True)}
            for row in rows
        ]
        payload = {
            "fields": fields,
            "items": items,
            "filter": "true",
            "markdown": "true",
            "sortable": "true",
        }
        json_data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        return f"```json:table\n{json_data}\n```\n"

    def page_filename(self, slug: str, uuid: str | None) -> str:
        return f"{uuid or slug}.md"
