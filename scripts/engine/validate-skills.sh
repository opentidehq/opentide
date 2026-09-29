#!/usr/bin/env bash
# Validate skills/*/SKILL.md against the Agent Skills spec and AGENTS.md index.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
fail=0
agents="$root/AGENTS.md"

python3 - "$root" "$agents" <<'PY'
import pathlib, re, sys
root = pathlib.Path(sys.argv[1])
agents = pathlib.Path(sys.argv[2]).read_text()
errors = []
skills = sorted(p.parent for p in root.joinpath("skills").glob("*/SKILL.md"))
if not skills:
    errors.append("no skills found")
for folder in skills:
    name = folder.name
    text = (folder / "SKILL.md").read_text()
    if not text.startswith("---\n"):
        errors.append(f"{name}: SKILL.md must start with YAML frontmatter")
        continue
    end = text.find("\n---\n", 4)
    if end == -1:
        errors.append(f"{name}: frontmatter is not closed")
        continue
    front = text[4:end]
    body = text[end + 5 :]
    if not body.strip():
        errors.append(f"{name}: body is empty")
    lines = text.count("\n") + (0 if text.endswith("\n") else 1)
    if lines > 500:
        errors.append(f"{name}: SKILL.md is {lines} lines; keep it under 500 and move detail to references/")
    fields = {}
    for line in front.splitlines():
        if not line.strip() or line.startswith(" "):
            continue
        if ":" not in line:
            errors.append(f"{name}: bad frontmatter line {line!r}")
            continue
        key, value = line.split(":", 1)
        fields[key.strip()] = value.strip()
    got = fields.get("name", "")
    if got != name:
        errors.append(f"{name}: frontmatter name {got!r} must match the directory")
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
        errors.append(f"{name}: directory name is not a valid skill name")
    desc = fields.get("description", "")
    if not desc:
        errors.append(f"{name}: description is empty")
    elif len(desc) > 1024:
        errors.append(f"{name}: description is {len(desc)} characters (max 1024)")
    if "Use when" not in desc:
        errors.append(f"{name}: description must say when to use the skill ('Use when')")
    if fields.get("license") != "EUPL-1.2":
        errors.append(f"{name}: license must be EUPL-1.2")
    if "author: OpenTideHQ" not in front:
        errors.append(f"{name}: metadata.author must be OpenTideHQ")
    needle = f"skills/{name}/SKILL.md"
    if needle not in agents:
        errors.append(f"{name}: AGENTS.md does not link {needle}")
    for ref in re.findall(r"references/([A-Za-z0-9_./-]+\.md)", body):
        path = folder / "references" / ref
        if not path.is_file():
            errors.append(f"{name}: missing {path.relative_to(root)}")
if errors:
    print("\n".join(errors))
    sys.exit(1)
print(f"skills ok ({len(skills)})")
PY
