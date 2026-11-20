import pytest
from fastapi.testclient import TestClient

from native_host_bridge.app import main as bridge_main

BRIDGE_TOKEN = "bridge-token-1234567890"
CANARY_TOKEN = "canary-token-abcdefghijkl"
HEADERS = {"X-Wraith-Bridge-Token": BRIDGE_TOKEN}
TARGET = "https://alpha.native.invalid/.wraith/native"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("NATIVE_HOST_BRIDGE_TOKEN", BRIDGE_TOKEN)
    monkeypatch.setenv("NATIVE_HOST_AGENT_TOKEN", BRIDGE_TOKEN)
    monkeypatch.setenv("NATIVE_HOST_ALLOWED_HOST_IDS", "alpha,beta")
    monkeypatch.setenv(
        "NATIVE_HOST_AGENTS",
        "alpha=http://agent-alpha:8011,beta=http://agent-beta:8011",
    )
    monkeypatch.setenv(
        "NATIVE_HOST_ALLOWED_ACTIONS",
        "load_probe,module_check,log_write,log_verify,process_self,cleanup",
    )
    monkeypatch.delenv("REDIS_URL", raising=False)
    return TestClient(bridge_main.app)


def job(**overrides):
    data = {
        "job_id": "job-1",
        "host_id": "alpha",
        "token": CANARY_TOKEN,
        "actions": ["module_check", "process_self"],
        "cleanup": False,
        "target_url": TARGET,
        "callback_url": "https://callbacks.native.invalid/hook",
        "ttl_seconds": 60,
    }
    data.update(overrides)
    return data


async def fake_forward(agent_url, payload):
    marker = f"wraith-native:{payload['job_id']}:{payload['token']}"
    return {
        "evidence": {
            "module_check": {"observed": False, "paths": [], "marker": marker},
            "process_self": {"pid": 7, "name": "uvicorn", "cmdline": "uvicorn"},
        },
        "cleanup": {"removed": [], "removed_count": 0},
    }


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_missing_and_wrong_bridge_token_rejected(client):
    assert client.post("/jobs", json=job()).status_code == 401
    assert client.post("/jobs", json=job(), headers={"X-Wraith-Bridge-Token": "wrong"}).status_code == 401


def test_unknown_host_and_unmapped_agent_rejected(client, monkeypatch):
    assert client.post("/jobs", json=job(host_id="gamma"), headers=HEADERS).status_code == 400
    monkeypatch.setenv("NATIVE_HOST_AGENTS", "beta=http://agent-beta:8011")
    response = client.post("/jobs", json=job(), headers=HEADERS)
    assert response.status_code == 400
    assert response.json()["detail"] == "no agent configured for host_id"


def test_action_allowlist_enforced(client, monkeypatch):
    monkeypatch.setenv("NATIVE_HOST_ALLOWED_ACTIONS", "module_check")
    response = client.post("/jobs", json=job(), headers=HEADERS)
    assert response.status_code == 400
    assert response.json()["detail"] == "action not allowed"


def test_cleanup_required_for_file_creating_actions(client):
    response = client.post("/jobs", json=job(actions=["log_write"]), headers=HEADERS)
    assert response.status_code == 400
    assert response.json()["detail"] == "cleanup required"


def test_unknown_action_rejected(client):
    response = client.post("/jobs", json=job(actions=["module_check", "dump_all"]), headers=HEADERS)
    assert response.status_code == 400
    assert response.json()["detail"] == "action not allowed"


def test_token_ttl_and_callback_constraints(client):
    assert client.post("/jobs", json=job(token="short"), headers=HEADERS).status_code == 400
    assert client.post("/jobs", json=job(ttl_seconds=0), headers=HEADERS).status_code == 400
    assert client.post("/jobs", json=job(ttl_seconds=3601), headers=HEADERS).status_code == 400
    response = client.post("/jobs", json=job(callback_url="https://evil.example/hook"), headers=HEADERS)
    assert response.status_code == 400
    assert response.json()["detail"] == "callback_url not allowed"


def test_success_response_shape_and_marker(client, monkeypatch):
    monkeypatch.setattr(bridge_main, "forward_job", fake_forward)
    response = client.post("/jobs", json=job(), headers=HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert set(data) == {"evidence", "cleanup", "target_url"}
    assert data["target_url"] == TARGET
    assert CANARY_TOKEN in data["evidence"]["marker"]
    assert CANARY_TOKEN in data["evidence"]["module_check_marker"]
    assert data["cleanup"] == {"removed": [], "removed_count": 0}


def test_dict_cleanup_is_accepted_for_file_actions(client, monkeypatch):
    seen = {}

    async def capture(agent_url, payload):
        seen.update(payload)
        return await fake_forward(agent_url, payload)

    monkeypatch.setattr(bridge_main, "forward_job", capture)
    response = client.post(
        "/jobs",
        json=job(actions=["log_write", "cleanup"], cleanup={"enabled": True}),
        headers=HEADERS,
    )
    assert response.status_code == 200
    assert seen["cleanup"] is True
    assert "log_write" in seen["actions"]


def test_agent_errors_are_generic(client, monkeypatch):
    async def failing(agent_url, payload):
        raise bridge_main.AgentError()

    monkeypatch.setattr(bridge_main, "forward_job", failing)
    response = client.post("/jobs", json=job(), headers=HEADERS)
    assert response.status_code == 502
    assert response.json()["detail"] == "host agent request failed"
    assert CANARY_TOKEN not in response.text


def test_killswitch_blocks_jobs(client, monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:6399/0")

    async def active():
        return True

    monkeypatch.setattr(bridge_main, "killswitch_active", active)
    assert client.post("/jobs", json=job(), headers=HEADERS).status_code == 503


def test_redis_unavailable_fails_closed(monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")
    import asyncio

    assert asyncio.run(bridge_main.killswitch_active()) is True
