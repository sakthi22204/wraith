#!/usr/bin/env bash
set -u
cd /home/sakthi/projects/wraith/wraith

echo "=== InvestigationCreate schema (graph_db/app/schema.py lines 41-56) ==="
timeout 12 sed -n "41,56p" graph_db/app/schema.py
echo
echo "=== POST /investigations route — body type + handler (routes.py) ==="
timeout 12 grep -nE "@router.post\(\"/investigations\"|def create_investigation" graph_db/app/routes.py
timeout 12 sed -n '/@router.post("\/investigations")/,/return repo.create_investigation/p' graph_db/app/routes.py | head -12
echo
echo "=== orchestrator graph-scope client base (which host:port + path prefix) ==="
timeout 12 grep -nE "GRAPH_DB|8001|base_url|api/v1" recon_orchestrator/app/graph_client.py | head
echo
echo "=== live env: does the RUNNING orchestrator already carry RECON_PROXY_URL? ==="
cid=$(docker ps --format "{{.Names}}" | grep -i "recon_orchestrator" | head -1)
echo "container=$cid"
timeout 12 docker inspect "$cid" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep -iE "RECON_PROXY" || echo "  (RECON_PROXY_URL empty/absent in running orchestrator env)"
