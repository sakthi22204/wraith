#!/usr/bin/env python3
"""Compile the vendored SKILL.md files into a small retrieval index.

The runner does not carry the skill corpus (the agent does). This writes a
compact JSON index next to the runner so the hybrid can rank relevant skills
and report automation coverage without reading 100 markdown files at runtime.

Run after ``scripts/sync_skills.sh`` or whenever a skill is added.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIRS = (
    (ROOT / "exploit_agent" / "skills_local", "local"),
    (ROOT / "exploit_agent" / "skills", "vendored"),
)
OUT_PATH = ROOT / "active_exploit_runner" / "app" / "skill_index.json"

STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "into", "when",
    "what", "your", "have", "will", "are", "not", "but", "can", "use",
    "using", "used", "each", "than", "then", "them", "they", "their",
    "you", "our", "its", "also", "one", "two", "all", "any", "how",
    "why", "who", "where", "which", "should", "must", "may", "only",
    "more", "most", "such", "over", "under", "about", "after", "before",
    "test", "testing", "tests", "check", "checks", "example", "examples",
}

ENDPOINT_RE = re.compile(
    r"/(?:api|rest|graphql|v1|v2|v3)/[A-Za-z0-9_\-/{}.:]+")
WORD_RE = re.compile(r"[a-z][a-z0-9_\-]{3,}")


def _front_matter(text: str) -> tuple[dict, str]:
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n?", text, re.S)
    if not match:
        return {}, text
    try:
        meta = yaml.safe_load(match.group(1)) or {}
    except Exception:
        meta = {}
    return (meta if isinstance(meta, dict) else {}), text[match.end():]


def _keywords(name: str, description: str, body: str) -> list[str]:
    counts: dict[str, int] = {}
    for word in WORD_RE.findall(f"{name} {description} {body[:12000]}".lower()):
        if word in STOPWORDS:
            continue
        counts[word] = counts.get(word, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return [word for word, _count in ranked[:30]]


def main() -> int:
    by_name = {}
    # Vendored first, local last: a local skill shadows a same-named vendored
    # copy, matching the runtime loader's first-match-wins layering.
    for directory, source in reversed(SKILLS_DIRS):
        for path in sorted(directory.glob("*/SKILL.md")):
            text = path.read_text(encoding="utf-8", errors="ignore")
            meta, body = _front_matter(text)
            name = str(meta.get("name") or path.parent.name)
            description = str(meta.get("description") or "")
            by_name[name] = {
                "name": name,
                "path": str(path.relative_to(ROOT)),
                "source": source,
                "description": description,
                "keywords": _keywords(name, description, body),
                "endpoints": sorted(set(ENDPOINT_RE.findall(body)))[:20],
            }
    skills = [by_name[name] for name in sorted(by_name)]

    OUT_PATH.write_text(
        json.dumps({"skills": skills}, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT_PATH} ({len(skills)} skills)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
