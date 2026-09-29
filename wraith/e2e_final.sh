#!/usr/bin/env bash
set -u
G=http://localhost:8001/api/v1
O=http://localhost:8002/api/v1

echo "=== [1] create FLIPKART investigation (exact scope: flipkart.com) ==="
FK=$(timeout 25 curl -sS -m 20 -X POST "$G/investigations" \
  -H "Content-Type: application/json" \
  -d '{"name": "Flipkart Proxy-E2E", "target": "flipkart.com", "platform": "automatic", "scope_domains": ["flipkart.com"]}')
printf "%s" "$FK" | timeout 10 sed -E "s/\"id\": \"([^\"]+)\"/\"id\": \"\1\"/" | head -c 200
echo
FK_ID=$(printf "%s" "$FK" | timeout 10 sed -nE "s/.*\"id\" *: *\"([^\"]+)\".*/\1/p" | timeout 6 python3 -c "import sys,json
for ln in sys.stdin: pass" 2>/dev/null || true)
[ -n "$FK_ID" ] || { echo "  !! no id -> raw: $FK"; exit 7; }
echo "  flipkart investigation_id = $FK_ID"
