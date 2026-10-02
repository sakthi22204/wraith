#!/usr/bin/env bash
# Run a service's tests where the infrastructure actually is.
#
# The suites in this repository are not self-contained. active_exploit_runner
# reaches postgres, redis, the live sandbox and juice_shop, kali_sandbox reaches
# juice_shop, and exploit_agent's tests import langchain_core, which only exists
# in its image. Run from the host, the database-dependent tests error at
# setup rather than failing, and an error at setup is easy to read as "not my
# problem" -- 40 tests had been quietly not running.
#
# So tests run inside the container, where those names resolve. Two rules make
# that trustworthy:
#
#   1. The compose override bind-mounts app/ and tests/, so the run exercises
#      the working tree rather than the copy baked into the image.
#   2. The gate secret is not overridden. The runner signs a grant with it and
#      the sandbox verifies the signature with the same one, so substituting a
#      test value produces grants the sandbox correctly refuses -- which shows
#      up as a 403 and looks like a product failure.
#
# Usage:
#   scripts/run_tests.sh              # every service
#   scripts/run_tests.sh runner       # active_exploit_runner only
#   scripts/run_tests.sh recon        # recon_orchestrator only
#   scripts/run_tests.sh agent        # exploit_agent only
#   scripts/run_tests.sh sandbox      # kali_sandbox only
#   scripts/run_tests.sh assessment   # assessment_service only
#   scripts/run_tests.sh reporting    # reporting only
#   scripts/run_tests.sh graph        # graph_db (non-container subset)
#   scripts/run_tests.sh unit         # no live services needed
set -euo pipefail

cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.test.yml)

# Resolved from compose rather than hardcoded: the container name carries the
# project prefix, so a hardcoded "active_exploit_runner-1" is wrong in any
# checkout whose directory is not called wraith.
container_id() {
  "${COMPOSE[@]}" ps -q "$1"
}

# `pytest -m "not integration"` is the subset that needs nothing running. It is
# the fast inner loop, not the whole suite, and the distinction is recorded in
# each project's pytest config so the marker means the same thing in both.
UNIT_ARGS=(-m "not integration")

start() {
  "${COMPOSE[@]}" up -d --build "$1" >/dev/null
}

wait_healthy() {
  local service="$1" port="$2" tries=0
  # python3, not python: the images ship no bare `python` shim, and asking for
  # one produces a wall of "executable file not found" that buries the real
  # wait loop.
  until "${COMPOSE[@]}" exec -T "$service" python3 -c \
        "import urllib.request; urllib.request.urlopen('http://localhost:${port}/health')" \
        2>/dev/null; do
    tries=$((tries + 1))
    if [ "$tries" -gt 60 ]; then
      echo "timed out waiting for $service" >&2
      return 1
    fi
    sleep 1
  done
}

# The graph suite reaches Neo4j through testcontainers, which needs a docker
# socket. Only docker_broker gets one in this stack, deliberately: handing it to
# a service so a test could be convenient would give that service the ability to
# start containers. The six modules below therefore cannot run here and are
# excluded rather than left to error at setup -- an error at setup reads as "not
# my problem", which is how 12 tests came to be silently skipped. The pure
# logic (severity adjudication, schema, auth) needs no database and does run.
GRAPH_NEEDS_CONTAINER=(
  --ignore=tests/test_api.py
  --ignore=tests/test_corroboration.py
  --ignore=tests/test_false_positive_patterns.py
  --ignore=tests/test_repository.py
  --ignore=tests/test_review_queue.py
  --ignore=tests/test_schema.py
)

run_in() {
  local service="$1"; shift
  local id
  id="$(container_id "$service")"
  if [ -z "$id" ]; then
    echo "no container for service '$service'" >&2
    return 1
  fi
  echo "=== ${service} tests ==="
  # The gate secret is inherited from the container, never passed in.
  docker exec -w /app "$id" python3 -m pytest "$@"
}

target="${1:-all}"

run_agent() {
  start exploit_agent
  # No health endpoint on this one; the app is a plain ASGI server behind the
  # port and is answering as soon as it binds.
  local id
  id="$(container_id exploit_agent)"
  echo "=== exploit_agent tests ==="
  docker exec -w /app "$id" python3 -m pytest tests/ -q
}

case "$target" in
  unit)
    # The runner has a genuine host-runnable subset. The sandbox does not: its
    # tests import the MCP SDK, which only exists in the image, so a host run
    # collects nothing and exits 5. That is reported rather than papered over --
    # the sandbox suite is container-only, so ask for it by name.
    (cd active_exploit_runner && python3 -m pytest "${UNIT_ARGS[@]}" -q)
    echo
    (cd recon_orchestrator && python3 -m pytest "${UNIT_ARGS[@]}" -q)
    echo
    echo "=== kali_sandbox ==="
    echo "container-only suite; use: scripts/run_tests.sh sandbox"
    echo "=== exploit_agent ==="
    echo "container-only suite; use: scripts/run_tests.sh agent"
    ;;

  runner)
    start active_exploit_runner
    wait_healthy active_exploit_runner 8004
    run_in active_exploit_runner tests/ -q
    ;;

  recon)
    start recon_orchestrator
    wait_healthy recon_orchestrator 8002
    run_in recon_orchestrator tests/ -q
    ;;

  agent)
    run_agent
    ;;

  sandbox)
    start kali_sandbox
    run_in kali_sandbox tests/ -q
    ;;

  assessment)
    start assessment_service
    wait_healthy assessment_service 8007
    run_in assessment_service tests/ -q
    ;;

  reporting)
    start reporting
    wait_healthy reporting 8006
    run_in reporting tests/ -q
    ;;

  graph)
    start graph_api
    wait_healthy graph_api 8001
    run_in graph_api tests/ -q "${GRAPH_NEEDS_CONTAINER[@]}"
    # test_api.py is the only module that exercises the HTTP routes rather than
    # the repository, so it is the one that would have caught the unguarded
    # writes. It was excluded with the rest because it needs testcontainers --
    # and the exclusion hid that it was additionally broken (async fixtures
    # without pytest_asyncio decorators, AsyncClient(app=...), a status enum
    # member that no longer exists). It is repaired, so it runs here on the host,
    # which does have a docker socket. The other five are still broken.
    #
    # First run after a cold Docker cache can exceed testcontainers' 120s log
    # wait while Neo4j downloads APOC; a re-run passes in about 30s.
    echo
    echo "=== graph_db route-level tests (host: needs a Neo4j testcontainer) ==="
    # -p no:cacheprovider: the container run leaves a root-owned .pytest_cache,
    # and writing to it from the host only produces a permissions warning.
    #
    # test_delete_investigation_recursive.py is included here because it shares
    # this file's loop_scope="session" convention. The other graph_db test
    # modules use bare @pytest.mark.asyncio, which binds the session-scoped
    # driver to a per-test loop and breaks with "got Future attached to a
    # different loop" -- that is why they are still excluded.
    (cd graph_db && python3 -m pytest tests/test_api.py tests/test_delete_investigation_recursive.py -q -p no:cacheprovider)
    ;;

  all)
    start active_exploit_runner
    start kali_sandbox
    start recon_orchestrator
    start assessment_service
    start reporting
    start graph_api
    wait_healthy active_exploit_runner 8004
    wait_healthy kali_sandbox 8000
    wait_healthy recon_orchestrator 8002
    wait_healthy assessment_service 8007
    wait_healthy reporting 8006
    wait_healthy graph_api 8001
    run_in active_exploit_runner tests/ -q
    run_in kali_sandbox tests/ -q
    run_in recon_orchestrator tests/ -q
    run_in assessment_service tests/ -q
    run_in reporting tests/ -q
    run_in graph_api tests/ -q "${GRAPH_NEEDS_CONTAINER[@]}"
    run_agent
    ;;

  *)
    echo "usage: $0 [all|runner|sandbox|recon|agent|assessment|reporting|graph|unit]" >&2
    exit 2
    ;;
esac
