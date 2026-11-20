# Wraith Native Host Bridge

Approved Phase 3 bridge between the sandbox `native_host_probe` tool and explicitly authorized endpoint agents.

## Setup

- `NATIVE_HOST_BRIDGE_TOKEN`: required service token sent by the sandbox as `X-Wraith-Bridge-Token`.
- `NATIVE_HOST_AGENT_TOKEN`: token used by the bridge toward endpoint agents. Defaults to the bridge token.
- `NATIVE_HOST_ALLOWED_HOST_IDS`: comma-separated canonical host IDs.
- `NATIVE_HOST_AGENTS`: comma-separated `host_id=http://agent:port` pairs.
- `NATIVE_HOST_ALLOWED_ACTIONS`: optional comma-separated subset of `load_probe,module_check,log_write,log_verify,process_self,cleanup`.
- `NATIVE_HOST_ALLOWED_CALLBACK_SUFFIXES`: optional extra callback host suffixes; `native.invalid` is always allowed.
- `NATIVE_HOST_AGENT_TIMEOUT`: agent forward timeout in seconds (default `2.0`).
- `REDIS_URL`: optional. When set, `wraith:killswitch` values `on`, `1`, or `true` block jobs; Redis failure fails closed.
- `NATIVE_HOST_BRIDGE_HOST` / `NATIVE_HOST_BRIDGE_PORT`: uvicorn bind, loopback by default.

Build and run from this directory:

```sh
docker build -t wraith-native-host-bridge .
docker run --rm -p 127.0.0.1:8010:8010 --env-file ../../.env wraith-native-host-bridge
```

`GET /health` is unauthenticated. `POST /jobs` requires the bridge token and answers with `evidence`, `cleanup`, and `target_url`.
