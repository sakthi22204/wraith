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

def test_dangerous_tool_unauthorized():
    # Attempt to call run_hydra without header
    response = client.post("/tools/run_hydra/call", json={"target": "t", "service": "s", "user": "u", "pass_list": "p"})
    assert response.status_code == 403
    assert "not authorized" in response.json()["detail"]

def test_dangerous_tool_authorized():
    # Attempt to call run_hydra with header (will still fail msf connection, but not 403)
    response = client.post(
        "/tools/run_hydra/call",
        json={"target": "t", "service": "s", "user": "u", "pass_list": "p"},
        headers={"X-Wraith-Caller": "active_exploit_runner"}
    )
    # It might fail with 500 or something else due to internal tool error, but NOT 403
    assert response.status_code != 403

def test_safe_tool_no_header():
    # Nmap is safe
    response = client.post("/tools/run_nmap_scan/call", json={"target": "127.0.0.1"})
    assert response.status_code != 403
