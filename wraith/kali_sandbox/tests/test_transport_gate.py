"""The gate has to hold on every transport, not only on the REST bridge.

`gate_request` used to be called from one place: the `/tools/{name}/call` bridge.
`mcp.run(transport="sse")` publishes the same tool set on the same object and
FastMCP dispatches straight to the tool function, so the gate was simply absent
from that path. Nothing about the request changed -- only which endpoint the
caller chose, and which of the two is not behind the grant check. A caller name
does not close that gap, because `X-Wraith-Caller` is a header the caller sets.

These tests drive the real thing rather than a stand-in for it: the low-level
`CallToolRequest` handler is the function FastMCP registers for SSE and streamable
HTTP in `_setup_handlers`, so invoking it here is the dispatch an SSE tool call
actually performs. A refusal observed at this seam is a refusal on the wire.

The bridge is covered too, but for the opposite failure: its grant is single use,
so the interceptor must not spend it a second time on the way through.
"""

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from fastapi.responses import JSONResponse

import mcp.types as types
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.fastmcp.tools.tool_manager import ToolManager

import mcp_servers.main as main_mod
from mcp_servers.main import GATED_NETWORK_TOOLS, mcp


class _StubProvider:
    """Stands in for a tool server, recording whether it was ever dispatched."""

    def __init__(self):
        self.calls = []
        self.mcp = self

    async def call_tool(self, name, body):
        self.calls.append((name, body))
        return (None, {"dispatched": True})


# Bodies complete enough that each tool reaches its provider if the gate does
# not stop it first, so a refusal can only come from the gate. Kept as a table
# rather than generated so that a tool whose required arguments change shows up
# as a test that needs updating, not as one that quietly stops proving anything.
_DISPATCHABLE_BODIES = {
    "run_nmap_scan": {"target": "127.0.0.1"},
    "run_nuclei_scan": {"target": "127.0.0.1"},
    "run_sqlmap": {"url": "http://127.0.0.1/"},
    "run_hydra": {"target": "127.0.0.1", "service": "ssh", "user": "u", "pass_list": "p"},
    "run_msf_module": {"module": "auxiliary/tcp/connect", "target": "127.0.0.1", "options": {}},
    "http_probe": {"url": "http://127.0.0.1/"},
    "http_probe_diff": {"url": "http://127.0.0.1/a", "variants": [{"url": "http://127.0.0.1/b"}]},
    "http_probe_race": {"url": "http://127.0.0.1/"},
    "http_probe_threshold": {"url": "http://127.0.0.1/", "count": 2},
    "http_probe_smuggle": {"url": "http://127.0.0.1/"},
    "http_probe_websocket_auth": {"url": "http://127.0.0.1/"},
}

# Which stubbed provider each tool dispatches through, so "was it reached?" can
# be asked of the specific tool rather than of the transport as a whole.
_PROVIDER_FOR_TOOL = {
    "run_nmap_scan": "nmap",
    "run_nuclei_scan": "nuclei",
    "run_sqlmap": "sqlmap",
    "run_hydra": "hydra",
    "run_msf_module": "metasploit",
    "list_msf_modules": "metasploit",
    "http_probe": "http_probe_server",
    "http_probe_diff": "http_probe_server",
    "http_probe_race": "http_probe_server",
    "http_probe_threshold": "http_probe_server",
    "http_probe_smuggle": "http_probe_server",
    "http_probe_websocket_auth": "http_probe_server",
}


@pytest.fixture
def stub_providers(monkeypatch):
    """Replace every provider whose tool would otherwise reach the network.

    Each provider is stubbed rather than the tool functions, so the assertions
    are about the tool never being reached at all -- not about a refusal raised
    from inside it.
    """
    stubs = {name: _StubProvider() for name in ("nmap", "nuclei", "sqlmap", "hydra",
                                                "metasploit", "http_probe_server")}
    for name, stub in stubs.items():
        monkeypatch.setattr(main_mod, name, stub)
    return stubs


def _call_raw(tool_name: str, arguments: dict):
    """Invoke the handler FastMCP registers for SSE/streamable tool calls."""
    import asyncio

    handler = mcp._mcp_server.request_handlers[types.CallToolRequest]
    request = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(name=tool_name, arguments=arguments),
    )
    return asyncio.run(handler(request))


def _texts(result) -> str:
    return " ".join(getattr(c, "text", "") or "" for c in result.root.content)


class TestSseDispatchIsGated:
    def test_the_gated_tool_is_never_reached_over_the_raw_mcp_path(self, stub_providers):
        """The bypass itself.

        Dispatched the way SSE dispatches, with a destination and no grant. It
        used to arrive at the tool function and run; it must be refused first.
        """
        result = _call_raw("run_nmap_scan", {"target": "127.0.0.1"})

        assert result.root.isError is True
        assert stub_providers["nmap"].calls == []

    def test_the_refusal_carries_the_reason_rather_than_a_crash(self, stub_providers):
        """A refusal has to say why, or it is indistinguishable from a failure."""
        result = _call_raw("run_nmap_scan", {"target": "127.0.0.1"})

        assert "grant" in _texts(result).lower()

    def test_the_caller_name_alone_does_not_authorize_the_raw_mcp_path(self, stub_providers):
        """`X-Wraith-Caller: exploit_agent` is a header the caller sets itself.

        The agent connects with exactly that header and no grant, so this is the
        call it would make. Presenting the name must not be enough.
        """
        token = main_mod.caller_context.set("exploit_agent")
        try:
            result = _call_raw("run_nmap_scan", {"target": "127.0.0.1"})
        finally:
            main_mod.caller_context.reset(token)

        assert result.root.isError is True
        assert stub_providers["nmap"].calls == []

    def test_every_traffic_sending_tool_is_refused_on_the_raw_mcp_path(self, stub_providers):
        """Exhaustive over the gated set, with bodies that would otherwise run.

        Each body is complete enough that the tool reaches its provider if the
        gate does not stop it first, so this is a per-tool version of the
        bypass above rather than a check that the arguments happened to be
        invalid. A tool added to the gated set without being covered here is
        the failure this catches.
        """
        for tool_name, body in sorted(_DISPATCHABLE_BODIES.items()):
            assert tool_name in GATED_NETWORK_TOOLS, f"{tool_name} is not gated"
            stub_providers[_PROVIDER_FOR_TOOL[tool_name]].calls.clear()

            result = _call_raw(tool_name, body)

            assert result.root.isError is True, f"{tool_name} was dispatched ungated"
            assert stub_providers[_PROVIDER_FOR_TOOL[tool_name]].calls == [], (
                f"{tool_name} reached its provider"
            )

    def test_a_missing_destination_is_refused_rather_than_guessed(self, stub_providers):
        """The gate cannot scope-check a destination it was not told."""
        result = _call_raw("run_sqlmap", {})

        assert result.root.isError is True
        assert "destination" in _texts(result).lower()
        assert stub_providers["sqlmap"].calls == []


class TestUngatedToolsAreUntouched:
    def test_a_tool_that_sends_no_traffic_still_dispatches(self, stub_providers):
        """Gating is on the tools that reach the network, not on the transport.

        Refusing everything would be safe and useless, and would hide the
        regression behind a service that appears to have no working tools.
        """
        result = _call_raw("list_msf_modules", {"search": "http"})

        assert result.root.isError is False


class TestTheInterceptorIsActuallyInThePath:
    def test_the_tool_manager_dispatch_is_wrapped(self):
        """Structural guard, so a library upgrade cannot quietly reopen this.

        The behaviour above proves the gate refuses; this proves why, and fails
        if a future FastMCP stops routing SSE through the wrapped method.
        """
        assert mcp._tool_manager.call_tool is not ToolManager.call_tool
        assert getattr(mcp._tool_manager.call_tool, "__name__", "") == "gated_call_tool"

    def test_every_transport_dispatches_through_the_wrapped_method(self):
        """SSE and streamable HTTP call `mcp.call_tool`, which delegates to the
        tool manager. That chain is what makes the wrap cover them, so it is
        asserted rather than assumed: if it is severed, the refusal tests above
        would be passing for a reason other than the one they are about.
        """
        handler = mcp._mcp_server.request_handlers[types.CallToolRequest]
        captured = {
            name: cell.cell_contents
            for name, cell in zip(handler.__code__.co_freevars, handler.__closure__ or ())
        }

        assert captured["func"].__func__ is type(mcp).call_tool
        assert captured["func"].__self__ is mcp


class TestTheBridgeStillGatesOnce:
    """A grant is single use, so the two gate calls must not both fire.

    The bridge gates, then calls `mcp.call_tool`, which comes back through the
    interceptor. If the interceptor gated again it would spend the same nonce a
    second time, and every authorised call would fail as a replay.
    """

    def _client(self):
        from fastapi import FastAPI

        app = FastAPI()
        for route in mcp._custom_starlette_routes:
            app.router.routes.append(route)
        return TestClient(app)

    def test_a_gated_tool_through_the_bridge_gates_exactly_once(self, monkeypatch, stub_providers):
        calls = []

        def _record(*args, **kwargs):
            calls.append((args, kwargs))
            return {"granted_host": "127.0.0.1", "rules": [], "investigation_id": "inv-1"}

        monkeypatch.setattr(main_mod, "gate_request", _record)

        response = self._client().post(
            "/tools/run_nmap_scan/call",
            json={"target": "127.0.0.1"},
            headers={"X-Wraith-Caller": "active_exploit_runner", "X-Wraith-Grant": "tok"},
        )

        assert response.status_code == 200
        assert len(calls) == 1
        assert stub_providers["nmap"].calls

    def test_the_bridge_still_answers_403_without_a_grant(self, stub_providers):
        """The interceptor is a backstop; the bridge's own answer is unchanged.

        A 403 and a JSON body are what the runner parses, so a gate refusal
        surfacing as a tool error here would be a behaviour change dressed up as
        a security fix.
        """
        response = self._client().post(
            "/tools/run_nmap_scan/call",
            json={"target": "127.0.0.1"},
            headers={"X-Wraith-Caller": "active_exploit_runner"},
        )

        assert response.status_code == 403
        assert stub_providers["nmap"].calls == []

    def test_the_gate_marker_does_not_outlive_the_bridge_call(self, monkeypatch, stub_providers):
        """One request cannot leave the next one ungated.

        The marker is what stops the double spend, so it also has to be the
        narrowest possible scope. A stale `True` would silently skip the gate
        for whatever ran next in the same worker.
        """
        real_gate = main_mod.gate_request
        monkeypatch.setattr(main_mod, "gate_request", lambda *a, **k: None)
        client = self._client()

        client.post(
            "/tools/run_nmap_scan/call",
            json={"target": "127.0.0.1"},
            headers={"X-Wraith-Caller": "active_exploit_runner"},
        )
        assert main_mod._gate_done.get() is False

        # With the real gate back in place, a call that did not come through the
        # bridge is still refused, even though one that did ran just before it.
        monkeypatch.setattr(main_mod, "gate_request", real_gate)
        stub_providers["nmap"].calls.clear()

        assert _call_raw("run_nmap_scan", {"target": "127.0.0.1"}).root.isError is True
        assert stub_providers["nmap"].calls == []
