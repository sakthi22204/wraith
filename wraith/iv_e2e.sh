#!/usr/bin/env bash
set -u
cd /home/sakthi/projects/wraith/wraith
G=http://localhost:8001/api/v1
O=http://localhost:8002/api/v1

echo "=== [0] which tool names does the orchestrator registry accept? (runtime source) ==="
timeout 15 grep -nE "KatanaTool|HttpxProbeTool|register|TOOL|name=" recon_orchestrator/app/orchestrator.py recon_orchestrator/app/tools/__init__.py 2>/dev/null | grep -iE "\"[a-z_]+tool\"" | head

echo
echo "=== [1] create Investigation: flipkart.com + myntra.com in scope ==="
INV=$(timeout 25 curl -sS -m 20 -X POST "$G/investigations" \
  -H "Content-Type: application/json" \
  -d '{"name": "FlipkartMyntra E2E", "target": "flipkart.com,myntra.com", "platform": "automatic", "scope_domains": ["flipkart.com", "myntra.com"]}' \
  -w "\n###HTTP=%{http_code}")
echo "$INV"
INV_ID=$(printf "%s" "$INV" | timeout 15 sed -nE "s/.*\"id\":\"([^\"]+)\".*/\1/p" | head -1)
[ -n "$INV_ID" ] || { echo "!! no investigation id returned"; exit 9; }
echo "investigation_id=$INV_ID"

echo
echo "=== [2] confirm scope resolves (orchestrator reads GET /investigations/<id>) ==="
timeout 20 curl -sS -m 15 "$G/investigations/$INV_ID" | timeout 15 sed -E "s/scope_domains/scope_domains/g" | head -c 400
echo
echo "=== [3] fire the real scan through the proxy sidecar (tools: katana + httpx_probe) ==="
timeout 35 curl -sS -m 30 -X POST "$O/recon/start" \
  -H "Content-Type: application/json" \
  -d "{\"investigation_id\": \"$INV_ID\", \"domains\": [\"www.flipkart.com\", \"www.myntra.com\"], \"tools\": [\"katana\", \"httpx_probe\"]}" \
  -w "\n###HTTP=%{http_code}\n" | tail -4

echo
echo "=== [4] poll session status up to 3 min ==="
SESSION="$INV_ID"
i=0
while [ $i -lt 18 ]; do
  i=$((i+1))
  sleep 10
  RESP=$(timeout 20 curl -sS -m 15 "$O/recon/$SESSION/status" 2>/dev/null)
  ST=$(printf "%s" "$RESP" | timeout 15 sed -E "s/.*\"status\":\"([^\"]+)\".*/\1/" | head -1)
  PROG=$(printf "%s" "$RESP" | timeout 15 sed -E "s/.*\"progress\":([0-9.]+).*/\1/" | head -1)
  TOOLST=$(printf "%s" "$RESP" | timeout 15 grep -oE "\"[a-z_]+\": *\"(running|completed|failed)\"" | head -3 | tr "\n" " ")
  echo "  [${i}] status=$ST progress=$PROG  tools=($TOOLST)"
  case "$ST" in completed|failed|partial) break;; esac
done

echo
echo "=== [5] INTERCEPTION EVIDENCE — did the sidecar actually capture + decrypt flipkart/myntra flows? ==="
echo "flows.mitm size + newest CA-trust check"
timeout 20 docker run --rm \
  -v wraith_mitmproxy_flows:/flows \
  busybox sh -c "ls -l /flows; echo ---; timeout 10 sh -c \"cat /flows/flows.mitm 2>/dev/null | head -c 200\" | sed -E \"s/([A-Za-z][A-Za-z0-9+._\/-]{20})/REDACTED/g\" || echo \\\"(binary or empty, expected -- spans still captured)\\\""
