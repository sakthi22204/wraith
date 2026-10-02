#!/usr/bin/env sh
set -u
cd /home/sakthi/projects/wraith/wraith

GRAPH=http://localhost:8001/api/v1
ORCH=http://localhost:8002/api/v1

# POST /programs and POST /recon/start are both token-guarded.
: "${ADMIN_API_TOKEN:?ADMIN_API_TOKEN must be set; guarded routes will 401 without it}"
AUTH="-H Authorization: Bearer $ADMIN_API_TOKEN"

echo "=== [1/5] register ONE program with BOTH domains in scope (scope guard requires it) ==="
timeout 20 curl -sS -m 15 -X POST "$GRAPH/programs" \
  -H "Content-Type: application/json" $AUTH \
  -d '{"name": "Flipkart+Myntra E2E", "platform": "public", "scope_domains": ["flipkart.com", "myntra.com"]}' \
  -w "\n  HTTP %{http_code}\n" | tail -6

echo
echo "=== [2/5] fire the orchestrator recon scan (katana proxy-flagged tool ONLY — the one with -proxy routing) ==="
timeout 25 curl -sS -m 20 -X POST "$ORCH/recon/start" \
  -H "Content-Type: application/json" $AUTH \
  -d '{"investigation_id": "flipkart-myntra-e2e", "domains": ["www.flipkart.com", "www.myntra.com"], "tools": ["katana"]}' \
  -w "\n  HTTP %{http_code}\n" | tail -8
