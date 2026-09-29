#!/usr/bin/env bash
# Wraith service watchdog.
#
# Why this exists: `restart: unless-stopped` is set on the core services in
# docker-compose.yml, but restart policies are not honoured by this Docker
# daemon (verified: a fresh container with --restart unless-stopped, SIGKILLed,
# records RestartCount=0 and stays down). That is why redis/postgres/broker
# would vanish mid-run and surface as opaque "Name or service not known" errors
# in the exploit agent.
#
# The compose healthchecks + depends_on conditions DO work, so this uses health
# rather than mere container-running state.
#
# Usage:
#   ops/watchdog.sh            # one pass, restart anything unhealthy
#   ops/watchdog.sh --loop     # stay resident, check every 30s
#
# Suitable for a systemd timer or cron entry:
#   */5 * * * * cd /path/to/wraith && ops/watchdog.sh >/dev/null 2>&1

set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

# Core services that expose an HTTP /health endpoint. Checked via the container's
# own Docker healthcheck (not localhost ports) because not every service
# publishes a port — kali_sandbox deliberately does not.
SERVICES=(
  "graph_db"
  "graph_api"
  "recon_orchestrator"
  "exploit_agent"
  "active_exploit_runner"
  "docker_broker"
  "kali_sandbox"
)

# Behind a compose profile or with no healthcheck — checked on running state.
STATE_ONLY=(
  "postgres"
  "redis"
  "ollama"
)

HEALTHY=""
declare -A FIXED=()

# healthy when the container reports a Docker healthcheck of "healthy", or when
# it is simply running and declares no healthcheck.
service_ok() {
  local cname="wraith-$1-1"
  local running health
  running=$(docker inspect "$cname" --format '{{.State.Running}}' 2>/dev/null)
  [ "$running" = "true" ] || return 1
  health=$(docker inspect "$cname" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' 2>/dev/null)
  case "$health" in
    # "starting" means still within start_period — booting, not broken. Restarting
    # it would loop forever, so treat it as acceptable and re-check next pass.
    healthy|starting|none) return 0 ;;
    *) return 1 ;;
  esac
}

container_running() {
  local name="$1"
  [ "$(docker inspect "wraith-${name}-1" --format '{{.State.Running}}' 2>/dev/null)" = "true" ]
}

restart_service() {
  local name="$1"
  if [ -n "${FIXED[$name]:-}" ]; then
    return
  fi
  FIXED[$name]=1
  echo "[watchdog] $(date -Is) restarting ${name}"
  docker compose --profile local-llm up -d --no-build "$name" >/dev/null 2>&1
}

pass() {
  echo "[watchdog] $(date -Is) pass complete"
}

run_pass() {
  for name in "${SERVICES[@]}"; do
    if service_ok "$name"; then
      HEALTHY="$HEALTHY $name"
    else
      restart_service "$name"
    fi
  done

  for name in "${STATE_ONLY[@]}"; do
    if container_running "$name"; then
      HEALTHY="$HEALTHY $name"
    else
      restart_service "$name"
    fi
  done

  echo "[watchdog] $(date -Is) healthy:$HEALTHY"
  if [ ${#FIXED[@]} -eq 0 ]; then
    pass
  else
    echo "[watchdog] $(date -Is) recovered ${#FIXED[@]} service(s): ${!FIXED[*]}"
  fi
  HEALTHY=""
  FIXED=()
}

if [ "${1:-}" = "--loop" ]; then
  echo "[watchdog] entering loop mode (30s interval), Ctrl-C to stop"
  while true; do
    run_pass
    sleep 30
  done
else
  run_pass
fi
