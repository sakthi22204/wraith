#!/usr/bin/env sh
set -u
cd /home/sakthi/projects/wraith/wraith

echo "=== STOP the sidecar (it is in a restart loop) ==="
timeout 30 docker compose --profile recon-proxy stop mitmproxy_sidecar 2>&1 | tail -2

echo
echo "=== fix ownership of the COMPOSE-PREFIXED named volumes the sidecar actually mounts ==="
echo "    (compose name = wraith_mitmproxy_ca + wraith_mitmproxy_flows; image runs uid 1000)"
timeout 90 docker run --rm \
  -v wraith_mitmproxy_ca:/ca \
  -v wraith_mitmproxy_flows:/flows \
  busybox sh -c 'chown -R 1000:1000 /ca /flows && echo PREFIXED_CHOWN_OK'
[ $? -eq 0 ] || { echo "CHOWN FAILED"; exit 1; }

echo
echo "=== remove the WRONG bare volumes I created earlier (plain mitmproxy_*, no prefix) ==="
timeout 30 docker volume rm mitmproxy_ca mitmproxy_flows 2>/dev/null && echo "removed bare mitmproxy_ca + mitmproxy_flows" || echo "no bare volumes to remove"

echo
echo "=== start sidecar again, watch it go from restart-loop to running ==="
timeout 60 docker compose --profile recon-proxy up -d --no-deps mitmproxy_sidecar 2>&1 | tail -2

echo
echo "=== wait up to ~5min for mitmdump to become RUNNING (it gen CA on first boot) ==="
i=0
while [ $i -lt 29 ]; do
  i=$((i+1))
  sleep 10
  status=$(timeout 20 docker inspect -f "{{.State.Status}}" wraith-mitmproxy_sidecar-1 2>/dev/null)
  echo "  [$i] status=$status"
  case "$status" in running) echo "SIDECAR RUNNING"; break;; esac
done

echo
echo "=== logs tail (want: proxy listening on :8080, CA saved, no EACCES) ==="
timeout 20 docker logs wraith-mitmproxy_sidecar-1 2>&1 | tail -8
