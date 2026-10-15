#!/bin/bash
# ops/wraith-phase.sh — Phase-based Wraith startup
# Usage: ./ops/wraith-phase.sh [phase]
#
# Why: Running all 13 containers simultaneously on a 16GB VM causes OOM.
# This script starts only the containers needed for each pipeline phase.
# Neo4j data persists in volumes between phases — data is never lost when
# stopping non-core containers.
#
# Core services (graph_db, graph_api, postgres, redis) stay up across ALL
# phases — they are the data layer. Only the workload services rotate.

set -e

CORE="graph_db graph_api postgres redis"

wait_healthy() {
  local service=$1
  local max=30
  local count=0
  echo "Waiting for $service to be healthy..."
  until [ "$(docker inspect --format='{{.State.Health.Status}}' \
    "$(docker compose ps -q $service 2>/dev/null)" 2>/dev/null)" = "healthy" ] \
    || [ $count -ge $max ]; do
    sleep 3
    count=$((count+1))
  done
  if [ $count -ge $max ]; then
    echo "WARNING: $service did not report healthy within timeout"
  fi
}

case "$1" in
  recon)
    echo "=== Starting Recon phase ==="
    echo "Containers: graph_db, graph_api, postgres, redis,"
    echo "            recon_orchestrator, docker_broker"
    echo "Estimated RAM: ~5GB"
    docker compose up -d $CORE recon_orchestrator docker_broker
    wait_healthy graph_db
    echo ""
    echo "Ready. Start a recon session via:"
    echo "  curl -X POST http://localhost:8002/api/v1/recon/start \\"
    echo "    -H 'Authorization: Bearer \$ADMIN_API_TOKEN' \\"
    echo "    -d '{\"domains\": [\"your-target.com\"]}'"
    echo ""
    echo "When recon completes, run: ./ops/wraith-phase.sh down-recon"
    ;;

  down-recon)
    echo "=== Stopping Recon phase containers ==="
    echo "Core (graph_db, graph_api, postgres, redis) stays up."
    echo "Recon data is saved in Neo4j."
    docker compose stop recon_orchestrator docker_broker
    echo "Done. Run ./ops/wraith-phase.sh exploit to continue."
    ;;

  exploit)
    echo "=== Starting Exploit phase ==="
    echo "Containers: core + exploit_agent, active_exploit_runner,"
    echo "            kali_sandbox, ollama"
    echo "Estimated RAM: ~6GB"
    docker compose up -d $CORE exploit_agent active_exploit_runner \
      kali_sandbox ollama
    wait_healthy kali_sandbox
    echo ""
    echo "Ready. Start an agent session via the frontend or API."
    echo "When exploit phase completes: ./ops/wraith-phase.sh down-exploit"
    ;;

  down-exploit)
    echo "=== Stopping Exploit phase containers ==="
    docker compose stop exploit_agent active_exploit_runner kali_sandbox ollama
    echo "Done. Run ./ops/wraith-phase.sh report to continue."
    ;;

  report)
    echo "=== Starting Reporting phase ==="
    echo "Containers: core + assessment_service, reporting, frontend"
    echo "Estimated RAM: ~5GB"
    docker compose up -d $CORE assessment_service reporting frontend
    echo ""
    echo "Ready. Open http://localhost:3000"
    echo "When done: ./ops/wraith-phase.sh down-report"
    ;;

  down-report)
    echo "=== Stopping Reporting phase containers ==="
    docker compose stop assessment_service reporting frontend
    echo "Done."
    ;;

  juice-shop)
    echo "=== Starting Juice Shop (local testing only) ==="
    docker compose up -d juice_shop
    echo "Juice Shop: http://juice_shop:3000 (internal only)"
    echo "Stop when done: ./ops/wraith-phase.sh down-juice-shop"
    ;;

  down-juice-shop)
    docker compose stop juice_shop
    echo "Juice Shop stopped."
    ;;

  all)
    echo "=== Starting full stack ==="
    echo "WARNING: Requires 12+ GB RAM. May cause instability on 16GB VMs."
    echo "Use phase commands instead for stability."
    read -p "Continue? (y/N) " confirm
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
      docker compose up -d
    else
      echo "Aborted. Use ./ops/wraith-phase.sh recon instead."
    fi
    ;;

  down-all)
    echo "=== Stopping all containers ==="
    docker compose down
    echo "All containers stopped. Volumes (Neo4j data) preserved."
    ;;

  status)
    echo "=== Wraith container status ==="
    docker compose ps
    echo ""
    echo "=== Memory usage ==="
    docker stats --no-stream --format \
      "table {{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}" 2>/dev/null | \
      grep -E "wraith|NAME" || docker stats --no-stream
    ;;

  *)
    echo "Wraith phase-based startup"
    echo ""
    echo "Usage: ./ops/wraith-phase.sh <command>"
    echo ""
    echo "Phase commands (recommended — lower RAM usage):"
    echo "  recon          Start core + recon containers (~5GB)"
    echo "  down-recon     Stop recon containers (keep core + data)"
    echo "  exploit        Start core + exploit containers (~6GB)"
    echo "  down-exploit   Stop exploit containers"
    echo "  report         Start core + reporting containers (~5GB)"
    echo "  down-report    Stop reporting containers"
    echo ""
    echo "Local testing:"
    echo "  juice-shop     Start Juice Shop container"
    echo "  down-juice-shop Stop Juice Shop"
    echo ""
    echo "Other:"
    echo "  all            Start everything (requires 12GB+ RAM)"
    echo "  down-all       Stop everything (preserves volume data)"
    echo "  status         Show container status + memory usage"
    echo ""
    echo "Typical flow:"
    echo "  ./ops/wraith-phase.sh recon"
    echo "  # wait for recon to complete"
    echo "  ./ops/wraith-phase.sh down-recon"
    echo "  ./ops/wraith-phase.sh exploit"
    echo "  # run agent session"
    echo "  ./ops/wraith-phase.sh down-exploit"
    echo "  ./ops/wraith-phase.sh report"
    ;;
esac
