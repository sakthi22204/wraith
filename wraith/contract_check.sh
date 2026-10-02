#!/usr/bin/env bash
set -u
cd /home/sakthi/projects/wraith/wraith

echo "=== InvestigationCreate schema (graph_db/app/schema.py lines 41-56) ==="
timeout 12 sed -n "41,56p" graph_db/app/schema.py
echo
echo "=== POST /investigations route — body type + handler (routes.py) ==="
# Routes live in graph_db/app/api/routes.py. The old check grepped
# graph_db/app/routes.py, which does not exist, so it silently matched nothing.
ROUTES=graph_db/app/api/routes.py
[ -f "$ROUTES" ] || { echo "FATAL: $ROUTES not found"; exit 1; }
timeout 12 grep -nE '@router.post\("/investigations"|def create_investigation' "$ROUTES"
echo
echo "=== the create route is token-guarded ==="
timeout 12 grep -nE '@router.post\("/investigations"' "$ROUTES" | grep -q "require_admin_token" \
  && echo "  OK: Depends(require_admin_token) present" \
  || { echo "  FAIL: create route is not token-guarded"; }
echo
echo "=== every browser-reachable write must have a panel proxy route ==="
PROXY_POST_ROUTES=(
  "frontend/src/app/api/investigations/route.ts"
  "frontend/src/app/api/findings/[id]/review/route.ts"
  "frontend/src/app/api/recon/start/route.ts"
  "frontend/src/app/api/recon/[sessionId]/cancel/route.ts"
  "frontend/src/app/api/agent/sessions/route.ts"
  "frontend/src/app/api/agent/sessions/[sessionId]/stop/route.ts"
)
for route in "${PROXY_POST_ROUTES[@]}"; do
  if grep -qs "export async function POST" "$route"; then
    echo "  OK: proxy POST route exists for ${route#frontend/src/app/api/}"
  else
    echo "  FAIL: no proxy POST route at $route"; exit 1
  fi
done
echo
echo "=== every proxy POST route must attach ADMIN_API_TOKEN ==="
for route in "${PROXY_POST_ROUTES[@]}"; do
  if grep -qs "ADMIN_API_TOKEN" "$route"; then
    echo "  OK: ${route#frontend/src/app/api/} references ADMIN_API_TOKEN"
  else
    echo "  FAIL: ${route#frontend/src/app/api/} does not attach the admin token"; exit 1
  fi
done
echo
echo "=== regression: graphApi must not POST directly to graph_db (token-guarded) ==="
if grep -A2 -E "fetch\(\`\\\$\{config\.graphDbUrl\}" frontend/src/lib/graphApi.ts 2>/dev/null \
     | grep -q "method: 'POST'"; then
  echo "  FAIL: graphApi still POSTs straight to graph_db -- would 401"; exit 1
else
  echo "  OK: no direct browser POST to graph_db"
fi
echo
echo "=== regression: the agent must never be started with an empty target_scope ==="
# startAgentSession used to be called with a literal [], which the panel proxy
# rejects with 400, and the catch turned that into a bare "Failed to start agent".
AGENT_PAGE="frontend/src/app/investigations/[investigationId]/page.tsx"
if grep -qE 'startAgentSession\([^)]*,\s*\[\]' "$AGENT_PAGE"; then
  echo "  FAIL: startAgentSession is called with an empty scope array"; exit 1
else
  echo "  OK: no empty-array target_scope"
fi
if grep -q "startAgentSession(investigationId as string, scopeDomains" "$AGENT_PAGE"; then
  echo "  OK: agent start uses the investigation's scopeDomains"
else
  echo "  FAIL: agent start does not use the investigation's scope domains"; exit 1
fi
echo
echo "=== negative assertion: token-less POST /investigations must be 401 ==="
if [ -z "${ADMIN_API_TOKEN:-}" ]; then
  echo "  SKIP: ADMIN_API_TOKEN not set (cannot assert the authenticated path)"
else
  CODE=$(timeout 15 curl -s -o /dev/null -w '%{http_code}' -m 10 -X POST \
    http://localhost:8001/api/v1/investigations \
    -H "Content-Type: application/json" \
    -d '{"name":"contract-check-negative","target":"example.com"}' 2>/dev/null || echo "000")
  case "$CODE" in
    401|403) echo "  OK: rejected with $CODE" ;;
    000)     echo "  SKIP: graph_api not reachable on :8001" ;;
    *)       echo "  FAIL: expected 401, got $CODE -- guard is not enforced"; exit 1 ;;
  esac
fi
echo
echo "=== orchestrator graph-scope client base (which host:port + path prefix) ==="
timeout 12 grep -nE "GRAPH_DB|8001|base_url|api/v1" recon_orchestrator/app/graph_client.py | head
echo
echo "=== live env: does the RUNNING orchestrator already carry RECON_PROXY_URL? ==="
cid=$(docker ps --format "{{.Names}}" | grep -i "recon_orchestrator" | head -1)
echo "container=$cid"
timeout 12 docker inspect "$cid" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep -iE "RECON_PROXY" || echo "  (RECON_PROXY_URL empty/absent in running orchestrator env)"

echo
echo "=== browser error handling: no status-blind 'throw new Error' in src/lib ==="
if grep -rn "throw new Error" frontend/src/lib/ ; then
  echo "  FAIL: above call sites discard the HTTP status, so the UI cannot say why"; exit 1
fi
echo "  OK: every failing call raises ApiError and keeps the status"
if ! grep -q "throw new ApiError(response.status, safeDetail(response.status, body, outOfScope))" frontend/src/lib/reconApi.ts; then
  echo "  FAIL: recon start no longer attaches the safe 400 scope detail"; exit 1
fi
echo "  OK: recon start attaches the safe scope detail"
if grep -q "toast.error('Failed to start recon')" frontend/src/app/investigations/\[investigationId\]/page.tsx; then
  echo "  FAIL: recon catch is hardcoded again"; exit 1
fi
echo "  OK: recon catch uses errorMessage"
if ! grep -q "setReconDomains(scopeDomains.join(', '))" frontend/src/app/investigations/\[investigationId\]/page.tsx; then
  echo "  FAIL: recon modal no longer prefills the authorized scope"; exit 1
fi
echo "  OK: recon modal prefills the authorized scope"
if ! grep -q "X-Wraith-Out-Of-Scope" frontend/src/app/api/recon/start/route.ts; then
  echo "  FAIL: recon proxy no longer forwards the rejected-domain header"; exit 1
fi
echo "  OK: recon proxy forwards the rejected-domain header"
if ! grep -q "out_of_scope_headers(out_of_scope)" recon_orchestrator/app/orchestrator.py; then
  echo "  FAIL: orchestrator no longer emits the rejected-domain header"; exit 1
fi
echo "  OK: orchestrator emits the sanitized rejected-domain header"
if grep -rn "config.assessmentUrl" frontend/src/ ; then
  echo "  FAIL: assessment is still called straight from the browser; that route needs the admin token"; exit 1
fi
echo "  OK: assessment reads go through the panel proxy"
if ! grep -q "ASSESSMENT_SERVICE_URL" frontend/src/app/api/assessments/\[investigationId\]/route.ts; then
  echo "  FAIL: assessment proxy no longer reads ASSESSMENT_SERVICE_URL"; exit 1
fi
echo "  OK: assessment proxy targets ASSESSMENT_SERVICE_URL"
