import pytest
from fastapi.testclient import TestClient

from native_host_agent.app import driver
from native_host_agent.app import main as agent_main

AGENT_TOKEN = "agent-token-1234567890"
CANARY_TOKEN = "canary-token-abcdefghijkl"
HEADERS = {"X-Wraith-Agent-Token": AGENT_TOKEN}


@pytest.fixture
def canary_dir(monkeypatch, tmp_path):
    path = tmp_path / "canary"
    monkeypatch.setenv("NATIVE_HOST_CANARY_DIR", str(path))
    return path


@pytest.fixture
def client(monkeypatch, canary_dir):
    monkeypatch.setenv("NATIVE_HOST_AGENT_TOKEN", AGENT_TOKEN)
    monkeypatch.delenv("NATIVE_HOST_PROBE_LIB", raising=False)
    return TestClient(agent_main.app)


def job(**overrides):
    data = {
        "job_id": "job-log",
        "token": CANARY_TOKEN,
        "actions": ["log_write", "log_verify"],
        "cleanup": True,
    }
    data.update(overrides)
    return data


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_missing_and_wrong_agent_token_rejected(client):
    assert client.post("/jobs", json=job()).status_code == 401
    assert client.post("/jobs", json=job(), headers={"X-Wraith-Agent-Token": "wrong"}).status_code == 401


def test_log_marker_write_verify_and_cleanup(client, canary_dir):
    response = client.post("/jobs", json=job(), headers=HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert CANARY_TOKEN in data["evidence"]["marker"]
    assert data["evidence"]["log_write"]["written"] is True
    assert data["evidence"]["log_verify"]["verified"] is True
    assert CANARY_TOKEN in data["evidence"]["log_verify"]["content"]
    assert data["cleanup"]["removed_count"] >= 1
    assert not (canary_dir / "job-log" / "canary.log").exists()
    assert not (canary_dir / "job-log").exists()


def test_cleanup_action_removes_prior_job_files(client, canary_dir):
    first = client.post("/jobs", json=job(cleanup=False, actions=["log_write"]), headers=HEADERS)
    assert first.status_code == 200
    log_path = canary_dir / "job-log" / "canary.log"
    assert log_path.is_file()

    second = client.post(
        "/jobs",
        json=job(actions=["cleanup"], cleanup=False),
        headers=HEADERS,
    )
    assert second.status_code == 200
    assert second.json()["cleanup"]["removed_count"] >= 1
    assert not log_path.exists()


def test_cleanup_does_not_remove_outside_paths(tmp_path):
    root = tmp_path / "canary"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("keep", encoding="utf-8")
    result = driver.cleanup_files(root, root / "job-x", [outside], "job-x", True)
    assert result["removed_count"] == 0
    assert outside.read_text(encoding="utf-8") == "keep"


def test_job_id_traversal_rejected(client, canary_dir):
    for job_id in ("../../etc/passwd", "..", "/etc/passwd"):
        response = client.post("/jobs", json=job(job_id=job_id), headers=HEADERS)
        assert response.status_code == 400
    assert not (canary_dir / "etc").exists()


def test_module_check_shape(client):
    response = client.post("/jobs", json=job(actions=["module_check"]), headers=HEADERS)
    assert response.status_code == 200
    detail = response.json()["evidence"]["module_check"]
    assert set(detail) >= {"observed", "paths", "marker"}
    assert isinstance(detail["observed"], bool)
    assert isinstance(detail["paths"], list)
    assert CANARY_TOKEN in detail["marker"]


def test_unsupported_load_probe_is_honest(client, monkeypatch):
    monkeypatch.delenv("NATIVE_HOST_PROBE_LIB", raising=False)
    response = client.post("/jobs", json=job(actions=["load_probe"]), headers=HEADERS)
    assert response.status_code == 200
    detail = response.json()["evidence"]["load_probe"]
    assert detail["loaded"] is False
    assert detail["unsupported"] is True
    assert detail["marker"] is None
    assert CANARY_TOKEN in detail["checked_marker"]

    monkeypatch.setenv("NATIVE_HOST_PROBE_LIB", "/definitely/not/a/library.so")
    response = client.post("/jobs", json=job(actions=["load_probe"]), headers=HEADERS)
    detail = response.json()["evidence"]["load_probe"]
    assert detail["loaded"] is False
    assert detail["unsupported"] is True


def test_process_self_is_bounded(client):
    response = client.post("/jobs", json=job(actions=["process_self"]), headers=HEADERS)
    assert response.status_code == 200
    detail = response.json()["evidence"]["process_self"]
    assert set(detail) == {"pid", "name", "cmdline"}
    assert isinstance(detail["pid"], int)


def test_unknown_action_rejected(client):
    response = client.post("/jobs", json=job(actions=["dump_all"]), headers=HEADERS)
    assert response.status_code == 400


def test_oversized_payload_rejected(client):
    response = client.post("/jobs", json=job(token="x" * 70000), headers=HEADERS)
    assert response.status_code == 413


def test_health_without_token(client):
    assert client.get("/health").status_code == 200
