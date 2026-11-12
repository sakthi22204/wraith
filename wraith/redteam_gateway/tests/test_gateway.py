"""The gateway is the only bridge from the agent to BeEF/Empire.

It must refuse before tasking anything unless the inbound caller is authorized,
C2 autonomy is explicitly full, the module is allowlisted, and the runner-issued
grant is bound to exactly this action, investigation and host.
"""
import base64
import hashlib
import hmac
import json

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import app.main as main
from app.grants import verify_grant

ADMIN = "gateway-admin-token"
SECRET = "gateway-gate-secret"


def _sign(payload: dict, secret: str = SECRET) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def enc(raw):
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{enc(body)}.{enc(hmac.new(secret.encode(), body, hashlib.sha256).digest())}"


def _grant(**overrides) -> str:
    import time
    payload = {
        "v": 1,
        "caller": "redteam_gateway",
        "inv": "inv-1",
        "host": "example.com:80",
        "cost": 1,
        "exp": int(time.time()) + 120,
        "nonce": "test",
        "tools": ["beef_hook"],
    }
    payload.update(overrides)
    return _sign(payload)


def _headers(token=ADMIN):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(main, "ADMIN_API_TOKEN", ADMIN)
    monkeypatch.setattr(main, "GATE_SECRET", SECRET)
    monkeypatch.setattr(main, "RUNNER_TOKEN", "runner-token")
    monkeypatch.setattr(main, "C2_AUTONOMY", "full")
    return TestClient(main.app)


def _body(**overrides):
    body = {
        "investigation_id": "inv-1",
        "action": "beef_hook",
        "target": "example.com",
        "c2_target": "",
        "module": "browser_details",
        "options": {},
        "actor_note": "test",
    }
    body.update(overrides)
    return body


def test_missing_or_wrong_admin_token_is_refused(client):
    assert client.post("/api/v1/c2/actions", json=_body()).status_code == 401
    assert client.post(
        "/api/v1/c2/actions", json=_body(), headers=_headers("wrong")
    ).status_code == 401


def test_autonomy_must_be_explicitly_full(client, monkeypatch):
    monkeypatch.setattr(main, "C2_AUTONOMY", "off")
    response = client.post("/api/v1/c2/actions", json=_body(), headers=_headers())
    assert response.status_code == 403
    assert "autonomy" in response.json()["detail"].lower()


def test_module_allowlist_is_enforced_before_runner_authorization(client, monkeypatch):
    monkeypatch.setattr(main, "BEEF_MODULES", {"browser_details"})
    response = client.post(
        "/api/v1/c2/actions",
        json=_body(action="beef_command", module="shell"),
        headers=_headers(),
    )
    assert response.status_code == 403
    assert "allowlist" in response.json()["detail"]


def test_runner_refusal_is_propagated(client, monkeypatch):
    async def denied(payload, actor_note):
        raise HTTPException(status_code=403, detail="out of scope")

    monkeypatch.setattr(main, "_authorize", denied)
    response = client.post("/api/v1/c2/actions", json=_body(), headers=_headers())
    assert response.status_code == 403
    assert "out of scope" in response.json()["detail"]


def test_grant_must_be_bound_to_the_request(client, monkeypatch):
    async def wrong_host(payload, actor_note):
        return {"grant": _grant(host="evil.test:80")}

    monkeypatch.setattr(main, "_authorize", wrong_host)
    response = client.post("/api/v1/c2/actions", json=_body(), headers=_headers())
    assert response.status_code == 403
    assert "does not match" in response.json()["detail"]


def test_beef_hook_returns_the_hook_url_only_after_authorization(client, monkeypatch):
    async def authorized(payload, actor_note):
        assert payload["action"] == "beef_hook"
        assert payload["investigation_id"] == "inv-1"
        return {"grant": _grant(), "target": "example.com"}

    monkeypatch.setattr(main, "_authorize", authorized)
    monkeypatch.setattr(main, "BEEF_PUBLIC_URL", "https://beef.example.test")
    response = client.post("/api/v1/c2/actions", json=_body(), headers=_headers())
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["result"]["hook_url"].startswith("https://beef.example.test")
    assert data["status"] == "completed"


def test_gateway_verifier_accepts_the_runner_grant_format():
    token = _grant(tools=["beef_command"], host="example.com:443")
    claims = verify_grant(token, SECRET)
    assert claims["tools"] == ["beef_command"]
    assert claims["host"] == "example.com:443"
