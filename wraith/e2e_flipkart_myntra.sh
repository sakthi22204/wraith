#!/usr/bin/env bash
set -u
cd /home/sakthi/projects/wraith/wraith
G=http://localhost:8001/api/v1
O=http://localhost:8002/api/v1

# POST /investigations and POST /recon/start are both token-guarded.
: "${ADMIN_API_TOKEN:?ADMIN_API_TOKEN must be set; guarded routes will 401 without it}"
AUTH=(-H "Authorization: Bearer $ADMIN_API_TOKEN")

refresh_scan() {
  # $1=inv_id  $2=merchant-label  $3==domain
  local inv="$1" label="$2" dom="$3"
  echo
  echo "======== [scan $label] POST $O/recon/start  investigation_id=$inv  domain=$dom ========"
  RESP=$(timeout 40 curl -sS -m 35 -X POST "$O/recon/start" \
    -H "Content-Type: application/json" \ "${AUTH[@]}" \
    -d "{\"investigation_id\": \"$inv\", \"domains\": [\"$dom\"], \"tools\": [\"katana\"]}")
  echo "  orchestration session: $(printf "%s" "$RESP" | timeout 12 grep -oE "\"investigation_id\" *: *\"[^\"]*\"|HTTP [0-9]{3}" | head -2)"
  SID=$(printf "%s" "$RESP" | timeout 12 sed -nE "s/.*\"id\" *: *\"([^\"]+)\".*/\1/p" | head -1)
  [ -n "$SID" ] && echo "  session_id=$SID  -> will poll" || echo "  ! no session id; raw: $(printf "%s" "$RESP" | head -c 180)"
}

echo "=== [A] create FLIPKART investigation (exact single scope: flipkart.com) ==="
FK=$(timeout 25 curl -sS -m 20 -X POST "$G/investigations" \
  -H "Content-Type: application/json" \ "${AUTH[@]}" \
  -d '{"name": "Flipkart Proxy-E2E", "target": "flipkart.com", "platform": "automatic", "scope_domains": ["flipkart.com"]}')
FK_ID=$(printf "%s" "$FK" | timeout 12 sed -nE "s/.*\"id\" *: *\"([^\"]+)\".*/\1/p" | head -1)
echo "  flipkart investigation_id=$FK_ID"
[ -n "$FK_ID" ] || { echo "  FAIL: $(printf "%s" "$FK" | head -c 200)"; exit 8; }

echo
echo "=== [B] create MYNTRA investigation (exact single scope: myntra.com) ==="
MY=$(timeout 25 curl -sS -m 20 -X POST "$G/investigations" \
  -H "Content-Type: application/json" \ "${AUTH[@]}" \
  -d '{"name": "Myntra Proxy-E2E", "target": "myntra.com", "platform": "automatic", "scope_domains": ["myntra.com"]}')
MY_ID=$(printf "%s" "$MY" | timeout 12 sed -nE "s/.*\"id\" *: *\"([^\"]+)\".*/\1/p" | head -1)
echo "  myntra investigation_id=$MY_ID"
[ -n "$MY_ID" ] || { echo "  FAIL: $(printf "%s" "$MY" | head -c 200)"; exit 8; }

echo
echo "=== [C] BOTH scan sessions (each through the SAME mitmproxy sidecar) ==="
refresh_scan "$FK_ID" "FLIPKART" "www.flipkart.com"
FK_SESSION="$SID"
refresh_scan "$MY_ID" "MYNTRA" "www.myntra.com"
MY_SESSION="$SID"

echo
echo "=== [D] persist for the polling stage (avoids re-scoping + proves both accepted) ==="
echo "FK_ID=$FK_ID"  >   /tmp/wraith_e2e_ids.env
echo "FK_SESSION=$FK_SESSION" >> /tmp/wraith_e2e_ids.env
echo "MY_ID=$MY_ID"  >> /tmp/wraith_e2e_ids.env
echo "MY_SESSION=$MY_SESSION" >> /tmp/wraith_e2e_ids.env
timeout 10 cat /tmp/wraith_e2e_ids.env
