# Test fixtures

Endpoints that exist to be tested against. None of these are part of the
product; nothing here should ever be deployed or exposed to a real user.

## `throttle_server.py`

A deliberately rate-limited endpoint, for proving the threshold harness
end-to-end.

`http_probe_threshold` is the only way to establish that a limiter is *absent*,
and the only way to establish that one is *present* at a given depth is to walk
into it. Mocked responses cannot demonstrate that a real `429` survives the HTTP
hop, that its headers arrive intact, or that `throttled_at` points at the
request that actually got refused. This fixture makes those claims checkable.

Two paths, so both sides of the grade are exercised:

| Path | Behaviour | Use it to check |
|---|---|---|
| `/limited` | `200` for the first `FIXTURE_LIMIT` requests, `429` after, with `Retry-After` and `X-RateLimit-*` | `throttling starts at request N`, `throttled_at`, `throttled_count` |
| `/open` | never refuses | `no rate limit is enforced` |
| `/reset` | clears the counters | starting a sweep from a known state |

The budget never refills (`FIXTURE_WINDOW=0`). That is deliberate: a sweep that
consumes the budget poisons the next one, and the refusal index is only
comparable between runs if each run starts clean — which is what `/reset` is
for. Setting `FIXTURE_WINDOW` to a positive number gives a real, expiring
window instead.

### Running it

```sh
docker run -d --name wraith_throttle_fixture \
  --network wraith_default -e FIXTURE_LIMIT=4 -e PORT=3001 \
  -v "$PWD/kali_sandbox/test_fixtures/throttle_server.py:/app/throttle_server.py:ro" \
  -w /app python:3.11-slim python3 throttle_server.py
```

Note the network: the probe containers live on `wraith_wraith_internal`, not
`wraith_default`, so a fixture started on the default network is unreachable
until it is also attached to the internal one:

```sh
docker network connect wraith_wraith_internal wraith_throttle_fixture
```

### Using it from a validation

The runner enforces scope before it sends anything, so pointing a validation at
the fixture needs a matching allow rule for that host. Scope rules are
authorization, not test setup — a rule added for a fixture is a real change to
what this investigation is permitted to touch, so add it deliberately and
remove it afterwards rather than leaving a wildcard behind:

```sql
-- add
INSERT INTO scope_rules (investigation_id, pattern, rule_type)
VALUES ('<investigation-id>', '*throttle_fixture*', 'ALLOW');

-- remove
DELETE FROM scope_rules WHERE id = <rule-id>;
```

With that in place, a validation that should be `CONFIRMED` against a limit of
4:

```json
{
  "url": "http://wraith_throttle_fixture:3001/limited",
  "method": "GET",
  "expected_result": "throttling starts at request 5",
  "vuln_type": "Missing Rate Limiting",
  "claimed_stage": "CONDITION_CONFIRMED",
  "threshold_count": 10
}
```

### Tearing down

```sh
docker rm -f wraith_throttle_fixture
```

and delete the scope rule. The runner should then refuse the host with
`BLOCKED_SCOPE`, which is the check that the fixture really is out of bounds and
not merely switched off.
