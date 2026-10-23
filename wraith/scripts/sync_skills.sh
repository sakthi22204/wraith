#!/usr/bin/env bash
# Re-vendor the pinned bug-bounty agent skill library.
#
# The runtime never fetches skills. exploit_agent/skills is a committed copy of
# a specific upstream commit, so an in-flight investigation cannot have its
# prompt changed underneath it by a branch moving. This script is the only
# supported way to move the pin.
#
# Usage:
#   scripts/sync_skills.sh                    # re-vendor the pin in UPSTREAM.md
#   SKILLS_SHA=<sha> scripts/sync_skills.sh   # move the pin to <sha>
#   SKILLS_REPO_URL=<url> scripts/sync_skills.sh
#
# Review the resulting git diff before committing. Skill renames are a code
# change: exploit_agent/app/skills/router.py maps skill names to vulnerability
# classes, and an unrecognised name is silently skipped at runtime.
set -euo pipefail

REPO_URL="${SKILLS_REPO_URL:-https://github.com/murrtada/bug-bounty-agent-skills.git}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/exploit_agent/skills"
UPSTREAM="$DEST/UPSTREAM.md"

if [[ ! -f "$UPSTREAM" ]]; then
  echo "error: $UPSTREAM is missing; cannot determine the current pin" >&2
  exit 1
fi

CURRENT_SHA="$(sed -n 's/^- Upstream commit: `\([0-9a-f]\{40\}\)`$/\1/p' "$UPSTREAM")"
PINNED_SHA="${SKILLS_SHA:-$CURRENT_SHA}"
if [[ -z "$PINNED_SHA" ]]; then
  echo "error: could not read the pin from $UPSTREAM" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Cloning $REPO_URL"
git clone --quiet "$REPO_URL" "$TMP/repo"
cd "$TMP/repo"
git checkout --quiet "$PINNED_SHA"

ACTUAL_SHA="$(git rev-parse HEAD)"
if [[ "$ACTUAL_SHA" != "$PINNED_SHA" ]]; then
  echo "error: requested $PINNED_SHA but checked out $ACTUAL_SHA" >&2
  exit 1
fi
TREE_SHA="$(git rev-parse HEAD:skills)"

# A symlink or a nested repository would escape the "plain committed files"
# promise this vendoring makes.
if find skills -type l | grep -q .; then
  echo "error: upstream skills tree contains symlinks" >&2
  exit 1
fi

mkdir -p "$DEST"
find "$DEST" -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} +
cp -a skills/. "$DEST"/
cp LICENSE TERMS.md "$DEST"/

cat > "$UPSTREAM" <<EOF
# Vendored skill library

This directory is a pinned copy of
[\`murrtada/bug-bounty-agent-skills\`](https://github.com/murrtada/bug-bounty-agent-skills).
It is vendored rather than fetched at runtime so that a prompt cannot change
under an investigation that is already running.

- Upstream commit: \`$ACTUAL_SHA\`
- Upstream \`skills/\` tree: \`$TREE_SHA\`
- Vendored on: $(date -u +%Y-%m-%d)
- License: MIT (see \`LICENSE\`); use is restricted to authorized targets (see
  \`TERMS.md\`)

## Updating

Run \`scripts/sync_skills.sh\` with \`SKILLS_SHA=<new-commit>\`. Review the diff of
\`exploit_agent/app/skills/router.py\` as well: the curated runtime allowlist and
the vuln-type mapping are tied to skill names, so a rename upstream is a code
change here, not just a copy.

Do not edit files in this directory by hand. Local changes are overwritten by
the next sync.
EOF

echo "Vendored $ACTUAL_SHA (skills tree $TREE_SHA) into $DEST"
echo "Review 'git status exploit_agent/skills' before committing."
