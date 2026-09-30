#!/usr/bin/env bash
# Run a service's tests where the infrastructure actually is.
#
# The suites in this repository are not self-contained. active_exploit_runner
# reaches postgres, redis, the live sandbox and juice_shop, and kali_sandbox
# reaches juice_shop. Run from the host, the database-dependent tests error at
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
#   scripts/run_tests.sh sandbox      # kali_sandbox only
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

case "$target" in
  unit)
    # The runner has a genuine host-runnable subset. The sandbox does not: its
    # tests import the MCP SDK, which only exists in the image, so a host run
    # collects nothing and exits 5. That is reported rather than papered over --
    # the sandbox suite is container-only, so ask for it by name.
    (cd active_exploit_runner && python3 -m pytest "${UNIT_ARGS[@]}" -q)
    echo
    echo "=== kali_sandbox ==="
    echo "container-only suite; use: scripts/run_tests.sh sandbox"
    ;;

  runner)
    start active_exploit_runner
    wait_healthy active_exploit_runner 8004
    run_in active_exploit_runner tests/ -q
    ;;

  sandbox)
    start kali_sandbox
    run_in kali_sandbox tests/ -q
    ;;

  all)
    start active_exploit_runner
    start kali_sandbox
    wait_healthy active_exploit_runner 8004
    wait_healthy kali_sandbox 8000
    run_in active_exploit_runner tests/ -q
    run_in kali_sandbox tests/ -q
    ;;

  *)
    echo "usage: $0 [all|runner|sandbox|unit]" >&2
    exit 2
    ;;
esac
