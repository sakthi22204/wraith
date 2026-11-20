# Wraith Native Host Agent

Bounded, non-destructive probe agent for explicitly authorized hosts. It never enumerates host processes and writes only inside its canary directory.

## Setup

- `NATIVE_HOST_AGENT_TOKEN`: required token sent by the bridge as `X-Wraith-Agent-Token`.
- `NATIVE_HOST_CANARY_DIR`: isolated directory for canary logs. Defaults to a temp-directory path.
- `NATIVE_HOST_PROBE_LIB`: optional benign shared library for `load_probe`. When unset or unusable, the action reports `loaded=false` and `unsupported=true`.
- `NATIVE_HOST_AGENT_HOST` / `NATIVE_HOST_AGENT_PORT`: uvicorn bind, loopback by default.

Build and run on the authorized host:

```sh
docker build -t wraith-native-host-agent .
docker run --rm -p 127.0.0.1:8011:8011 --env-file ../../.env wraith-native-host-agent
```

Keep the bind on loopback unless the bridge reaches the agent through an explicitly approved network path. `GET /health` is unauthenticated; `POST /jobs` requires the agent token.
