import pytest
from fastapi.testclient import TestClient
from mcp_servers.main import mcp
from fastapi import FastAPI
from fastapi.responses import JSONResponse

# Create a test FastAPI app that includes the FastMCP custom routes
app = FastAPI()
# This is a bit internal, but we want to test our custom route
for route in mcp._custom_starlette_routes:
    # Wrap the handler to return a JSONResponse since Starlette expects a Response object
    # but our custom_route handler currently returns a list (which FastAPI would usually handle)
    app.router.routes.append(route)

client = TestClient(app)


def _message(response) -> str:
    """Refusals come back in two shapes depending on which check refused.

    `verify_caller` raises an HTTPException, which FastAPI renders as
    {"detail": ...}; a gate refusal is raised inside the tool body and comes back
    as {"error": ...}. Tests assert on the reason, not on which wrapper won.
    """
    body = response.json()
    if isinstance(body, dict):
        return str(body.get("detail") or body.get("error") or "")
    return str(body)


def test_dangerous_tool_unauthorized():
    # Attempt to call run_hydra without header
    response = client.post("/tools/run_hydra/call", json={"target": "t", "service": "s", "user": "u", "pass_list": "p"})
    assert response.status_code == 403
    assert "not authorized" in response.json()["detail"]

def test_dangerous_tool_authorized():
    """An authorized caller name is no longer enough on its own.

    This used to assert `!= 403` for a hydra call carrying only
    `X-Wraith-Caller`, which is the request reading back its own header. run_hydra
    is now gated, so the gate refuses it for want of a signed grant before the
    caller name is even considered.
    """
    response = client.post(
        "/tools/run_hydra/call",
        json={"target": "t", "service": "s", "user": "u", "pass_list": "p"},
        headers={"X-Wraith-Caller": "active_exploit_runner"}
    )
    # 403 either way: refused at the caller check or at the gate. Both are the
    # gate refusing to act on a self-asserted identity.
    assert response.status_code == 403
    message = _message(response).lower()
    assert "grant" in message or "not authorized" in message


def test_nmap_is_gated_not_safe():
    """nmap was treated as a 'safe tool' here and reached the binary on nothing
    but a caller header. It is in GATED_NETWORK_TOOLS now."""
    response = client.post("/tools/run_nmap_scan/call", json={"target": "127.0.0.1"})
    assert response.status_code == 403
    message = _message(response).lower()
    assert "grant" in message or "not authorized" in message


def test_caller_name_does_not_substitute_for_a_grant():
    """The specific confusion this change removes: presenting the runner's name
    used to be the whole authorisation. It is now necessary but not sufficient."""
    from mcp_servers.main import GATED_NETWORK_TOOLS

    assert "run_hydra" in GATED_NETWORK_TOOLS
    response = client.post(
        "/tools/run_hydra/call",
        json={"target": "127.0.0.1", "service": "ssh", "user": "u", "pass_list": "p"},
        headers={"X-Wraith-Caller": "active_exploit_runner", "X-Wraith-Grant": "forged.token"},
    )
    assert response.status_code == 403

def test_get_caller_from_headers():
    from unittest.mock import MagicMock, patch
    from mcp_servers.main import get_caller

    mock_request = MagicMock()
    mock_request.headers.get.return_value = "test_agent_caller"

    with patch("mcp_servers.main.mcp.get_context") as mock_get_context:
        mock_ctx = MagicMock()
        mock_ctx.request_context.request = mock_request
        mock_get_context.return_value = mock_ctx

        assert get_caller() == "test_agent_caller"
