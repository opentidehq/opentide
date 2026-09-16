"""Template file helpers.

YAML skeletons are rendered from Pydantic ``FieldInfo`` in
``opentide.generation.pydantic_skeleton``. The JSON Schema walker
``gen_template`` was removed (issue #227).
"""

from __future__ import annotations

from pathlib import Path


def indent_template(template_path: Path | str, identation: int) -> bool:
    """Prefix every line in *template_path* with *identation* spaces."""
    path = Path(template_path)
    indented = [
        " " * identation + line
        for line in path.read_text(encoding="utf-8").splitlines(keepends=True)
    ]
    path.write_text("".join(indented), encoding="utf-8")
    return True


def replace_strings_in_file(file_path: Path | str, strings: list[str], replacement: str) -> bool:
    path = Path(file_path)
    buffer: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines(keepends=True):
        for word in strings:
            if word in line:
                line = line.replace(word, replacement)
        buffer.append(line)
    path.write_text("".join(buffer), encoding="utf-8")
    return True


def remove_blanks(path: Path | str) -> bool:
    file_path = Path(path)
    clean = "".join(
        line
        for line in file_path.read_text(encoding="utf-8").splitlines(keepends=True)
        if not line.isspace()
    )
    file_path.write_text(clean, encoding="utf-8")
    return True
