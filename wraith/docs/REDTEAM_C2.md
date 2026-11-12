# Redteam C2 bridge

Status: **implemented, image-pinned, unit-tested, and live-smoke-tested.** BeEF hook delivery, login, module resolution and tasking against a real hooked Chromium session are verified. Empire login and the agent-tasking path are verified with an agent id that does not exist (expected 404); tasking a real agent requires an actual Empire agent.

Wraith's agent can task BeEF and Empire, but only through the redteam gateway.
The gateway is a thin, auditable bridge: the runner remains the sole authority
for engagement mode, scope, aggressiveness, killswitch, rate limits and audit.
Nothing in the agent or the gateway can widen those decisions.

```
agent (run_c2_action)
  -> POST redteam_gateway /api/v1/c2/actions
       -> POST active_exploit_runner /api/v1/redteam/authorize
            (killswitch, ENGAGEMENT_MODE, scope, allow_aggressive, rate limit)
       <- 120s HMAC grant bound to caller/investigation/host/tool
       (verify grant, C2_AUTONOMY, module allowlist)
  -> BeEF or Empire
```

## Enable it

The stack is opt-in; the default `docker compose up` never starts C2.

```bash
# .env
ENGAGEMENT_MODE=redteam          # or both; wapt disables /redteam/authorize
C2_AUTONOMY=full                 # anything else makes the gateway refuse tasking
ADMIN_API_TOKEN=...
EXPLOIT_RUNNER_BROKER_TOKEN=...
WRAITH_GATE_SECRET=...

BEEF_USERNAME=wraith
BEEF_PASSWORD=<strong-password>  # required by the BeEF entrypoint
EMPIRE_USERNAME=empireadmin
EMPIRE_PASSWORD=<strong-password> # required by the Empire image

docker compose --profile redteam up -d
```

Only the gateway is published, and only on loopback (`127.0.0.1:8010`). BeEF,
Empire and the target-facing hop stay on `wraith_redteam`; the gateway is the
only bridge from `wraith_internal`.

Pinned images:

| Service | Image |
|---|---|
| BeEF | `beefproject/beef@sha256:d2eeff1f55819ea6ab14f3b0c678697bd0cee00d6cfc820e277b698fa0395f49` |
| Empire | `bcsecurity/empire:v7.0.2@sha256:7615e3e320908552a0705d63f34da0d4bbc1ab5da3f1b0da5732e7c7f3e81248` |

The BeEF image upstream publishes only `latest` and one old commit tag, so the
digest is pinned even though the image dates from 2022. Upgrading means
re-validating login, module ids and the `/api/modules/{session}/{id}` response
shape before changing the digest.

## Credentials and BeEF's rotating token

BeEF generates its REST token at startup from a random seed and rotates it. It
cannot be set through an environment variable. The gateway therefore logs in
with `BEEF_USERNAME`/`BEEF_PASSWORD` and uses the returned token for the
request. `BEEF_API_TOKEN` is only for supplying a current token by hand.

At container start, the BeEF entrypoint generates a per-start config from the
image's `/beef/config.yaml`, replaces the default `beef:beef` credentials,
restricts the admin UI to loopback and RFC1918 ranges, and sets the public port
from `BEEF_PUBLIC_URL`. That last setting matters: BeEF builds `hook.js` from
its configured port, not the port the request arrived on. The published mapping
is `127.0.0.1:3001 -> beef:3000`, so if `BEEF_PUBLIC_URL` says port 3001 the hook
calls back to 3001; without it the hook advertises 3000 and never registers.

Empire uses the normal OAuth2 password flow: `POST /token` with form fields,
then `POST /api/v2/agents/{agent}/tasks/module` with
`{"module_id": "...", "options": {...}}` and a bearer token. Its first admin is
seeded from `EMPIRE_DATABASE__DEFAULTS__USERNAME` /
`EMPIRE_DATABASE__DEFAULTS__PASSWORD`; Compose passes `EMPIRE_USERNAME` /
`EMPIRE_PASSWORD` into those settings and refuses to start if the password is
empty. Those same values are what the gateway logs in with.

## Actions

| Action | `c2_target` | `module` | Notes |
|---|---|---|---|
| `beef_hook` | unused | not required | Returns the hook URL. Delivering it is a separate authorized step. |
| `beef_command` | BeEF session id | BeEF module key, e.g. `fingerprint_browser` | Module id is resolved from `GET /api/modules`; the allowlist is checked before tasking. |
| `empire_task` | Empire agent id | slash-delimited module id | Must be in `EMPIRE_MODULE_ALLOWLIST`. |

`target` is the in-scope host the action is attributed to. It is what the
scope and aggressiveness rules evaluate; `c2_target` is a session/agent id and
is never treated as a network host.

## Controls

- **Module allowlists** are the primary control. Defaults are read-only or
  situational-awareness modules, not persistence, credential dumping, lateral
  movement or exfiltration.
- **`C2_AUTONOMY`** must be exactly `full`; anything else refuses every action.
- **`ENGAGEMENT_MODE`** must be `redteam` or `both`; `wapt` refuses
  `/redteam/authorize`.
- **Killswitch** is checked by the runner and fails closed if unreachable.
- **Scope and `allow_aggressive`** are evaluated by the runner against `target`.
- **Rate limit** is charged by the runner before a grant is minted.
- **Grant binding** is verified by the gateway: caller, investigation, target
  authority and action must all match, and the grant expires after 120s.
- **Audit** records `c2_authorize:<action>`, investigation, target, actor,
  `c2_target`, module and grant issuance.

The gateway has a deliberate reset: it has no scope database and no killswitch
of its own, so it cannot become a second source of authority.

## Testing

```bash
scripts/run_tests.sh gateway     # host, no services
scripts/run_tests.sh runner      # includes /redteam/authorize tests
scripts/run_tests.sh agent       # includes the agent -> gateway path
```

The gateway adapter tests mock HTTP and pin the paths/fields above. They are
not a substitute for a live smoke test against the pinned images.

## Known gaps

- No live BeEF or Empire session has been driven end-to-end yet.
- Empire's module options are passed through as supplied; required-option
  validation happens in Empire and returns a 400.
- BeEF's 2022 image is the only digest available from upstream.
- `redteam_toolkit/powersploit/` is content-only; it is reachable through an
  allowlisted Empire task, not a direct adapter.
- Empire has no persistent volume in the Compose profile, so recreating the
  container resets its agents/listeners and re-seeds the admin from the current
  credentials.
