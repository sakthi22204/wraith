#!/usr/bin/env bash
# Install the vendored skill library for a developer's coding agent.
#
# This is the Phase 0 developer workflow: a human agent (opencode, Claude Code,
# ...) reads the same pinned skills the runtime uses. It installs from
# exploit_agent/skills in this checkout, not from a second upstream clone, so
# what you read locally and what an investigation loads are the same bytes.
#
# Usage:
#   scripts/install_dev_skills.sh                 # opencode (default)
#   scripts/install_dev_skills.sh claude
#   scripts/install_dev_skills.sh both
#   scripts/install_dev_skills.sh opencode --dry-run
#
# Skills are copied, not symlinked: a running agent can be started from any
# directory, and a symlink into a checkout that later moves would break it.
set -euo pipefail

AGENT="${1:-opencode}"
MODE="${2:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/exploit_agent/skills"

if [[ ! -d "$SRC" ]]; then
  echo "error: $SRC is missing; run scripts/sync_skills.sh first" >&2
  exit 1
fi

install_into() {
  local dest="$1"
  local label="$2"
  if [[ "$MODE" == "--dry-run" ]]; then
    echo "[dry-run] would install $(find "$SRC" -mindepth 1 -maxdepth 1 -type d | wc -l) skills into $dest ($label)"
    return
  fi
  mkdir -p "$dest"
  # Copy only skill directories. LICENSE/TERMS.md stay with the vendor tree;
  # agent runtimes enumerate directories, and stray files are noise.
  find "$SRC" -mindepth 1 -maxdepth 1 -type d -exec cp -a {} "$dest"/ \;
  echo "Installed skills into $dest ($label)"
}

case "$AGENT" in
  opencode)
    install_into "${XDG_CONFIG_HOME:-$HOME/.config}/opencode/skills" "opencode"
    ;;
  claude)
    install_into "$HOME/.claude/skills" "Claude Code"
    ;;
  both)
    install_into "${XDG_CONFIG_HOME:-$HOME/.config}/opencode/skills" "opencode"
    install_into "$HOME/.claude/skills" "Claude Code"
    ;;
  *)
    echo "usage: $0 [opencode|claude|both] [--dry-run]" >&2
    exit 2
    ;;
esac
