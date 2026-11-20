import asyncio
import contextlib
import http.server
import socket
import socketserver
import threading
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import mcp_servers.injection_harness_server as harness_mod
import mcp_servers.main as main_mod
from mcp_servers.gate import GATED_NETWORK_TOOLS


HARNESS_TOOLS = (
    "browser_probe", "oob_probe", "smtp_capture",
    "file_export_probe", "raw_socket_probe", "native_host_probe",
)


@pytest.fixture
def harness(monkeypatch):
    monkeypatch.setattr(harness_mod, "settings", SimpleNamespace(
        REDIS_URL="",
        OOB_CALLBACK_HOST="127.0.0.1",
        OOB_CALLBACK_PORT=8091,
        OOB_DNS_PORT=0,
        OOB_MAX_WAIT_SECONDS=15.0,
        SMTP_CAPTURE_HOST="127.0.0.1",
        SMTP_CAPTURE_PORT=0,
        SMTP_ALLOWED_RECIPIENT_DOMAINS=".invalid,corp.test",
        NATIVE_HOST_BRIDGE_URL="",
        NATIVE_HOST_BRIDGE_TOKEN="",
        NATIVE_HOST_PROBE_TIMEOUT=5.0,
    ))
    monkeypatch.setattr(harness_mod, "_oob_memory", {})
    monkeypatch.setattr(harness_mod, "_oob_tokens", {})
    monkeypatch.setattr(harness_mod, "_oob_expiry", {})
    monkeypatch.setattr(harness_mod, "_dns_transport", None)
    return harness_mod.InjectionHarnessServer()


class TestRegistration:
    def test_all_six_tools_are_registered_and_gated(self):
        names = {tool.name for tool in main_mod.mcp._tool_manager.list_tools()}
        for tool in HARNESS_TOOLS:
            assert tool in names
            assert tool in GATED_NETWORK_TOOLS


class TestBrowserProbe:
    def test_unavailable_browser_is_unsupported_and_never_fabricates_a_marker(self, harness, monkeypatch):
        monkeypatch.setattr(harness_mod, "async_playwright", None)
        result = asyncio.run(harness.browser_probe(
            url="http://juice_shop/", marker="MARKER-123"
        ))
        assert result["marker_seen"] is False
        assert result["status"] == "unsupported"
        assert result["error"]
        assert result["body"] == ""
        assert result["console"] == []
        assert result["dom"] == ""

    def test_marker_is_collected_from_the_rendered_page(self, harness, monkeypatch):
        class _Page:
            def __init__(self):
                self.handler = None

            def on(self, event, handler):
                self.handler = handler

            async def goto(self, url, **kwargs):
                self.handler(SimpleNamespace(text="console: BODY-MARKER"))

            async def add_script_tag(self, content=None):
                return None

            async def wait_for_timeout(self, value):
                return None

            async def evaluate(self, script):
                return "BODY-MARKER text"

            async def content(self):
                return "<html><body>BODY-MARKER text</body></html>"

        class _Browser:
            async def new_page(self):
                return _Page()

            async def close(self):
                return None

        class _Chromium:
            async def launch(self, **kwargs):
                return _Browser()

        @contextlib.asynccontextmanager
        async def _playwright():
            yield SimpleNamespace(chromium=_Chromium())

        monkeypatch.setattr(harness_mod, "async_playwright", _playwright)
        result = asyncio.run(harness.browser_probe(
            url="http://juice_shop/", marker="BODY-MARKER", script="window.x=1"
        ))
        assert result["status"] == "ok"
        assert result["marker_seen"] is True
        assert "BODY-MARKER" in result["body"]
        assert any("BODY-MARKER" in line for line in result["console"])

    def test_browser_probe_applies_identity_headers(self, harness, monkeypatch):
        applied = {}

        class _Page:
            def __init__(self):
                self.handler = None

            def on(self, event, handler):
                self.handler = handler

            async def set_extra_http_headers(self, headers):
                applied.update(headers)

            async def goto(self, url, **kwargs):
                return None

            async def evaluate(self, script):
                return ""

            async def content(self):
                return "<html></html>"

        class _Browser:
            async def new_page(self):
                return _Page()

            async def close(self):
                return None

        class _Chromium:
            async def launch(self, **kwargs):
                return _Browser()

        @contextlib.asynccontextmanager
        async def _playwright():
            yield SimpleNamespace(chromium=_Chromium())

        monkeypatch.setattr(harness_mod, "async_playwright", _playwright)
        result = asyncio.run(harness.browser_probe(
            url="http://juice_shop/", marker="MARKER-123",
            headers={"Cookie": "session=abc"},
        ))
        assert result["status"] == "ok"
        assert applied == {"Cookie": "session=abc"}

    def test_reflected_body_marker_alone_does_not_confirm_execution(self, harness, monkeypatch):
        class _Page:
            def __init__(self):
                self.handler = None

            def on(self, event, handler):
                self.handler = handler

            async def goto(self, url, **kwargs):
                return None

            async def evaluate(self, script):
                return "BODY-MARKER text"

            async def content(self):
                return "<html><body>BODY-MARKER text</body></html>"

        class _Browser:
            async def new_page(self):
                return _Page()

            async def close(self):
                return None

        class _Chromium:
            async def launch(self, **kwargs):
                return _Browser()

        @contextlib.asynccontextmanager
        async def _playwright():
            yield SimpleNamespace(chromium=_Chromium())

        monkeypatch.setattr(harness_mod, "async_playwright", _playwright)
        result = asyncio.run(harness.browser_probe(
            url="http://juice_shop/?q=BODY-MARKER", marker="BODY-MARKER"
        ))
        assert result["status"] == "ok"
        assert "BODY-MARKER" in result["body"]
        assert result["marker_seen"] is False
        assert result["console"] == []

    def test_selector_signal_marks_dom_observation(self, harness, monkeypatch):
        marker = "SEL-MARKER"

        class _Page:
            def __init__(self):
                self.handler = None

            def on(self, event, handler):
                self.handler = handler

            async def goto(self, url, **kwargs):
                self.handler(SimpleNamespace(
                    text="__wraith_selector__SEL-MARKER__wraith_selector__"
                ))

            async def add_script_tag(self, content=None):
                return None

            async def wait_for_timeout(self, value):
                return None

            async def evaluate(self, script):
                return ""

            async def content(self):
                return "<html><body></body></html>"

        class _Browser:
            async def new_page(self):
                return _Page()

            async def close(self):
                return None

        class _Chromium:
            async def launch(self, **kwargs):
                return _Browser()

        @contextlib.asynccontextmanager
        async def _playwright():
            yield SimpleNamespace(chromium=_Chromium())

        monkeypatch.setattr(harness_mod, "async_playwright", _playwright)
        result = asyncio.run(harness.browser_probe(
            url="http://juice_shop/", marker=marker, selector="body"
        ))
        assert result["selector"] == "body"
        assert result["selector_matched"] is True


class TestOOBProbe:
    def test_callback_is_token_bound_and_redacts_secrets(self, harness):
        result = asyncio.run(harness.oob_probe(
            target_url="http://juice_shop/", oob_wait_seconds=0
        ))
        token = result["token"]
        assert f"/oob/{token}" in result["callback_url"]
        assert token in result["dns_callback"]
        assert result["interactions"] == []

        class _Request:
            path_params = {"token": token}
            method = "POST"
            headers = {"Authorization": "Bearer secret-token", "X-Trace": "abc"}
            query_params = {"q": "value", "token": "secret-value"}
            url = SimpleNamespace(path=f"/oob/{token}")

            async def body(self):
                return b"payload=1&password=hunter2"

        callback = asyncio.run(harness.oob_callback_route(_Request()))
        assert callback.status_code == 200
        stored = harness_mod._read_interactions(token)
        assert len(stored) == 1
        assert stored[0]["headers"]["Authorization"] == "[REDACTED]"
        assert stored[0]["query"]["token"] == "[REDACTED]"
        assert "hunter2" not in stored[0]["body"]

    def test_unknown_token_has_no_storage_and_no_route(self, harness):
        class _Request:
            path_params = {"token": "not-a-token"}
            method = "GET"
            headers = {}
            query_params = {}
            url = SimpleNamespace(path="/oob/not-a-token")

            async def body(self):
                return b""

        response = asyncio.run(harness.oob_callback_route(_Request()))
        assert response.status_code == 404
        assert harness_mod._read_interactions("not-a-token") == []

    def test_callback_route_is_registered_on_the_app(self, harness):
        result = asyncio.run(harness.oob_probe(target_url="http://juice_shop/"))
        token = result["token"]
        with TestClient(main_mod.mcp.sse_app()) as client:
            response = client.get(f"/oob/{token}", params={"q": "hello"})
        assert response.status_code == 200
        assert response.json()["status"] == "recorded"
        assert any(i.get("query", {}).get("q") == "hello"
                   for i in harness_mod._read_interactions(token))

    def test_interactions_are_bounded(self, harness):
        result = asyncio.run(harness.oob_probe(target_url="http://juice_shop/"))
        token = result["token"]
        for index in range(harness_mod.MAX_INTERACTIONS + 50):
            harness_mod._store_interaction(token, {"type": "http", "index": index})
        assert len(harness_mod._read_interactions(token)) <= harness_mod.MAX_INTERACTIONS


class TestSMTPCapture:
    def test_disallowed_recipient_is_rejected_before_any_mail_is_sent(self, harness):
        result = asyncio.run(harness.smtp_capture(
            target_url="http://juice_shop/", recipient="victim@example.com",
            subject="test", body="hello",
        ))
        assert result["status"] == "rejected"
        assert result["headers"] == []
        assert result["body"] == ""

    def test_allowed_recipient_is_captured(self, harness):
        result = asyncio.run(harness.smtp_capture(
            target_url="http://juice_shop/", recipient="victim@probe.invalid",
            subject="marker-subject", body="marker-body",
        ))
        assert result["status"] == "ok"
        assert result["headers"]["Subject"] == "marker-subject"
        assert "marker-body" in result["body"]

    def test_bound_smtp_port_returns_structured_error(self, harness, monkeypatch):
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen()
        port = blocker.getsockname()[1]
        monkeypatch.setattr(harness_mod.settings, "SMTP_CAPTURE_PORT", port)
        try:
            result = asyncio.run(harness.smtp_capture(
                target_url="http://juice_shop/", recipient="victim@probe.invalid",
                subject="test", body="hello",
            ))
        finally:
            blocker.close()
        assert result["status"] == "error"
        assert result["headers"] == []
        assert result["body"] == ""
        assert result["error"]


class _CSVHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        payload = b"name,formula\nalice,\"=cmd|'/c calc'!A1\"\nbob,normal\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/csv")
        self.send_header("Content-Disposition", 'attachment; filename="users.csv"')
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        return


class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)
        self.request.sendall(b"HTTP/1.1 200 OK\r\nX-Test: yes\r\nContent-Length: 0\r\n\r\n")


@pytest.fixture
def csv_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CSVHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/users.csv"
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


@pytest.fixture
def tcp_server():
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _TCPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


class TestFileAndSocketProbes:
    def test_csv_formula_cells_are_detected(self, harness, csv_server):
        result = asyncio.run(harness.file_export_probe(url=csv_server))
        assert result["status"] == "ok"
        assert result["download_filename"] == "users.csv"
        assert any("cmd|" in cell["value"] for cell in result["cells"])
        assert all(cell["row"] >= 1 for cell in result["cells"])

    def test_csv_detection_does_not_execute(self):
        cells = harness_mod.csv_formula_cells("=1+1,=SUM(A1)\n-5,+ok\n")
        assert len(cells) == 3

    def test_raw_socket_header_lines_and_response_count(self, harness, tcp_server):
        result = asyncio.run(harness.raw_socket_probe(
            url=f"http://127.0.0.1:{tcp_server}/",
            raw_socket_payload="PING\r\n",
            timeout=2.0,
        ))
        assert result["status"] == "ok"
        assert result["response_count"] >= 1
        assert any("X-Test: yes" in line for line in result["header_lines"])
