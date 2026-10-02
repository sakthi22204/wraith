#!/usr/bin/env bash
# Remove recon stderr pollution from the knowledge graph.
#
# Some recon tools log to stderr as well as stdout. When a tool's stderr and
# stdout were merged into one stream and parsed line by line, structured log
# lines were parsed as results, so logfmt fragments became evidence nodes:
#
#   Host     time="2026-10-02T07
#   Endpoint time="2026-10-02T07:21:59Z" level=warning msg="error reading
#            config: Config file /root/.gau.toml not found, ..."
#
# The parsers no longer accept embedded results (see
# recon_orchestrator/app/tools/base.py::iter_path_or_url_lines and the
# regression tests in recon_orchestrator/tests/test_stderr_not_evidence.py), so
# new runs cannot add these. Nodes already written by earlier runs stay in the
# graph, and a junk Host still shows up as an in-scope host, which reads as a
# real discovery on the dashboard and in the reports.
#
# Deleting them is a mutation of the audit record, so this script never deletes
# by default: with no arguments it only prints what it would remove. Pass
# --apply to actually delete, and read the printed list first.
#
# Why the match is narrow:
#
#   The obvious predicate is "value contains =", which is what these nodes have
#   in common with each other. It is wrong here: a legitimate endpoint URL with
#   a query string (https://host/path?a=b) contains "=" too, and Endpoint is the
#   largest label in this graph. A cleanup that quietly deleted real findings
#   would be worse than the pollution it removes. So the match is anchored to
#   the logfmt prefix the leak actually produced, "time=\"", at the start of the
#   value. No hostname and no URL begins with that. The script prints every
#   candidate with its label and id so the list can be eyeballed.
#
# Usage:
#   scripts/cleanup_recon_stderr_nodes.sh              # list only, deletes nothing
#   scripts/cleanup_recon_stderr_nodes.sh --apply      # delete, after confirmation
#   scripts/cleanup_recon_stderr_nodes.sh --force      # delete, skipping the sanity cap
set -euo pipefail

cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.test.yml)

# Nothing is deleted unless a large number of nodes match. A count this high
# means the predicate is matching something other than the leak it was written
# for, so it stops for inspection instead of proceeding.
SANITY_CAP="${SANITY_CAP:-50}"

APPLY=0
FORCE=0
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    --force) FORCE=1 ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
  esac
done

container_id() { "${COMPOSE[@]}" ps -q "$1"; }

cid="$(container_id graph_db)"
if [ -z "$cid" ]; then
  echo "graph_db container not found; start the stack first" >&2
  exit 1
fi

# Authenticated in-container, reading the password out of NEO4J_AUTH
# ("neo4j/<password>", the form compose passes to the neo4j image) rather than
# from the host. Passing it as a host argument would put it in the process
# table and shell history; this repo treats it as a secret.
cypher() {
  docker exec -i "$cid" sh -c \
    'exec cypher-shell -u neo4j -p "${NEO4J_AUTH#neo4j/}" --format plain'
}

# Anchored to the logfmt prefix. Kept in one place so the listing, the count and
# the delete can never drift apart -- a delete matching more than the listing
# showed is the failure mode worth designing out.
POLLUTION_MATCH='(n:Host OR n:Endpoint) AND (n.value STARTS WITH '\''time="'\'' OR n.url STARTS WITH '\''time="'\'')'

count_nodes() {
  cypher <<CYPHER | tail -1
MATCH (n) WHERE $POLLUTION_MATCH RETURN count(*) AS n;
CYPHER
}

echo "Recon stderr pollution in the graph:"
echo

total="$(count_nodes)"

cypher <<CYPHER
MATCH (n)
WHERE $POLLUTION_MATCH
RETURN labels(n)[0] AS label,
       n.id AS id,
       coalesce(n.value, n.url) AS value,
       size([(n)--() | 1]) AS relationships
ORDER BY label, value;
CYPHER

echo
echo "$total node(s) match."

if [ "$total" -eq 0 ]; then
  echo "Nothing to do."
  exit 0
fi

if [ "$APPLY" -eq 0 ]; then
  echo
  echo "Dry run: nothing was deleted. Re-run with --apply to remove the above."
  exit 0
fi

if [ "$total" -gt "$SANITY_CAP" ] && [ "$FORCE" -eq 0 ]; then
  echo
  echo "Refusing to delete $total nodes: over the sanity cap of $SANITY_CAP."
  echo "That many matches suggests the predicate is catching real data."
  echo "Inspect the list above, then re-run with --force if it is still correct."
  exit 1
fi

# Written before the delete so the exact rows are recoverable by hand. The id is
# kept because it is what a report or an investigation reference would carry.
backup="recon_stderr_nodes_$(date +%Y%m%d_%H%M%S).tsv"
cypher <<CYPHER > "$backup"
MATCH (n)
WHERE $POLLUTION_MATCH
RETURN labels(n)[0] AS label, n.id AS id, coalesce(n.value, n.url) AS value;
CYPHER
echo
echo "Saved the rows being deleted to $backup"

echo "Deleting $total node(s)..."
cypher <<CYPHER
MATCH (n) WHERE $POLLUTION_MATCH DETACH DELETE n;
CYPHER

remaining="$(count_nodes)"
echo "Deleted. $remaining node(s) still match the pattern."
if [ "$remaining" -ne 0 ]; then
  echo "Unexpected: the pattern still matches nodes. Re-run to see what is left."
  exit 1
fi
