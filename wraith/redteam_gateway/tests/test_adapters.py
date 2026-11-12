"""BeEF tasking must use the API the daemon actually exposes.

BeEF rotates its REST token on startup and tasks modules by numeric id, not by
module key. A client that assumes a static token or a `/sessions/.../execute`
route fails at the one moment it matters. These tests pin the login, module
lookup and tasking path.
"""
import pytest

from app import adapters
from app.adapters import BeefClient, C2Error


class FakeResponse:
    def __init__(self, status_code=200, data=None, text=""):
        self.status_code = status_code
        self._data = data
        self.text = text

    def json(self):
        if self._data is None:
            raise ValueError("no json")
        return self._data


class FakeClient:
    calls = []
    modules = [
        {"id": 86, "class": "BeEF::Core::Command::BrowserDetails", "name": "Browser Details"},
        {"id": 120, "class": "BeEF::Core::Command::GetVisitedURLs", "name": "Get Visited URLs"},
    ]
    task_status = 200

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, params=None, json=None):
        self.calls.append(("POST", url, params, json))
        if url.endswith("/api/admin/login"):
            return FakeResponse(200, {"success": True, "token": "rotated-token"})
        if "/api/modules/" in url:
            return FakeResponse(self.task_status, {"success": True, "command_id": "7"})
        return FakeResponse(404, {"error": "not found"})

    async def get(self, url, params=None):
        self.calls.append(("GET", url, params, None))
        if url.endswith("/api/modules"):
            return FakeResponse(200, self.modules)
        return FakeResponse(404, {"error": "not found"})


@pytest.fixture
def fake_http(monkeypatch):
    FakeClient.calls = []
    FakeClient.task_status = 200
    monkeypatch.setattr(adapters.httpx, "AsyncClient", FakeClient)
    return FakeClient


@pytest.mark.asyncio
async def test_beef_logs_in_and_tasks_by_numeric_module_id(fake_http):
    client = BeefClient(base_url="http://beef:3000", username="wraith", password="secret")

    result = await client.execute("session-1", "browser_details", {"x": "y"})

    assert result["command_id"] == "7"
    assert fake_http.calls[0] == (
        "POST", "http://beef:3000/api/admin/login", None,
        {"username": "wraith", "password": "secret"},
    )
    assert fake_http.calls[1][:3] == ("GET", "http://beef:3000/api/modules", {"token": "rotated-token"})
    assert fake_http.calls[2] == (
        "POST", "http://beef:3000/api/modules/session-1/86",
        {"token": "rotated-token"}, {"x": "y"},
    )


@pytest.mark.asyncio
async def test_beef_matches_camelcase_module_class(fake_http):
    client = BeefClient(base_url="http://beef:3000", token="current-token")
    await client.execute("session-1", "get_visited_urls", {})
    assert fake_http.calls[-1][1] == "http://beef:3000/api/modules/session-1/120"


@pytest.mark.asyncio
async def test_beef_accepts_the_object_keyed_module_listing(fake_http, monkeypatch):
    """Live BeEF returns {"0": {...}, "1": {...}}, not a bare array."""
    monkeypatch.setattr(fake_http, "modules", {
        "0": {"id": 86, "class": "BeEF::Core::Command::BrowserDetails", "name": "Browser Details"},
    })
    client = BeefClient(base_url="http://beef:3000", token="current-token")

    await client.execute("session-1", "browser_details", {})

    assert fake_http.calls[-1][1] == "http://beef:3000/api/modules/session-1/86"


@pytest.mark.asyncio
async def test_beef_requires_credentials_or_a_current_token(fake_http):
    client = BeefClient(base_url="http://beef:3000", token="", username="", password="")
    with pytest.raises(C2Error, match="credentials"):
        await client.execute("session-1", "browser_details", {})


@pytest.mark.asyncio
async def test_unknown_beef_module_is_refused(fake_http):
    client = BeefClient(base_url="http://beef:3000", token="current-token")
    with pytest.raises(C2Error, match="not found"):
        await client.execute("session-1", "shell", {})
    assert not any("/api/modules/session-1/" in call[1] for call in fake_http.calls)


@pytest.mark.asyncio
async def test_beef_task_failure_is_an_error(fake_http):
    fake_http.task_status = 403
    client = BeefClient(base_url="http://beef:3000", token="current-token")
    with pytest.raises(C2Error, match="HTTP 403"):
        await client.execute("session-1", "browser_details", {})


class FakeEmpireClient:
    calls = []
    token = "empire-token"
    task_status = 201

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, data=None, json=None, headers=None):
        self.calls.append(("POST", url, data, json, headers))
        if url.endswith("/token"):
            return FakeResponse(200, {"access_token": self.token, "token_type": "bearer"})
        if url.endswith("/tasks/module"):
            return FakeResponse(self.task_status, {"id": 42, "status": "queued"})
        return FakeResponse(404, {"error": "not found"})


@pytest.fixture
def fake_empire(monkeypatch):
    FakeEmpireClient.calls = []
    FakeEmpireClient.task_status = 201
    monkeypatch.setattr(adapters.httpx, "AsyncClient", FakeEmpireClient)
    monkeypatch.setenv("EMPIRE_USERNAME", "empireadmin")
    monkeypatch.setenv("EMPIRE_PASSWORD", "secret")
    return FakeEmpireClient


@pytest.mark.asyncio
async def test_empire_logs_in_and_tasks_module_on_agent(fake_empire):
    client = adapters.EmpireClient(base_url="http://empire:1337/api/v2")

    result = await client.execute(
        "AGENT1", "powershell/situational_awareness/host/win32processes", {"x": "y"}
    )

    assert result["id"] == 42
    assert fake_empire.calls[0] == (
        "POST", "http://empire:1337/token",
        {"username": "empireadmin", "password": "secret"}, None, None,
    )
    assert fake_empire.calls[1] == (
        "POST", "http://empire:1337/api/v2/agents/AGENT1/tasks/module", None,
        {"module_id": "powershell/situational_awareness/host/win32processes",
         "options": {"x": "y"}},
        {"Authorization": "Bearer empire-token"},
    )


@pytest.mark.asyncio
async def test_empire_accepts_current_bearer_token(fake_empire):
    client = adapters.EmpireClient(base_url="http://empire:1337", token="current")
    await client.execute("AGENT1", "module/path", {})
    assert len(fake_empire.calls) == 1
    assert fake_empire.calls[0][4] == {"Authorization": "Bearer current"}


@pytest.mark.asyncio
async def test_empire_task_failure_is_an_error(fake_empire):
    fake_empire.task_status = 400
    client = adapters.EmpireClient(base_url="http://empire:1337", token="current")
    with pytest.raises(C2Error, match="HTTP 400"):
        await client.execute("AGENT1", "module/path", {})
