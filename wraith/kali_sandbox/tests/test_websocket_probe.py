"""Tests for the WebSocket upgrade authentication harness.

As with the smuggling harness, the verdict matters more than the mechanics, so
these run a real RFC 6455 server in-process and check the harness against one
that is open and one that is not. A WebSocket handshake is a plain HTTP GET,
which is the whole reason this is worth testing: a browser will send one
cross-origin with the victim's cookies attached and never prompt, so "did the
server check who was asking" has to be established empirically.
"""
import base64
import hashlib
import socket
import socketserver
import threading
import time

import pytest

from mcp_servers.http_probe_server import (
    BLOCKED_WEBSOCKET_HEADERS,
    WS_FINDING_ACCEPT_NOT_VALIDATED,
    WS_FINDING_DATA_BEFORE_AUTH,
    WS_FINDING_UNAUTHENTICATED_UPGRADE,
    WS_FINDING_UPGRADE_REJECTED,
    WS_GUID,
    HttpProbeServer,
    ProbeWebSocketAuth,
)

pytestmark = pytest.mark.anyio


# --------------------------------------------------------------------------
# A minimal RFC 6455 server, with selectable openness.
# --------------------------------------------------------------------------

class _WSHandler(socketserver.BaseRequestHandler):
    """Completes a handshake, optionally with a correct Accept, then speaks first.

    ``bad_accept`` answers 101 while echoing the wrong value, which is the
    cross-site WebSocket hijacking condition: a malicious page can then read the
    socket because nothing proved the reply belonged to its own request.
    """

    require_auth = False
    bad_accept = False
    push_first = True

    def handle(self):
        conn = self.request
        buf = b""
        try:
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            head, _, rest = buf.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    name, _, value = line.partition(":")
                    headers[name.strip().lower()] = value.strip()

            if self.require_auth and "authorization" not in headers:
                conn.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                return

            if headers.get("upgrade", "").lower() != "websocket":
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                return

            key = headers.get("sec-websocket-key", "")
            expected = base64.b64encode(
                hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
            accept = "AAAAAAAAAAAAAAAAAAAAAAAAAAA=" if self.bad_accept else expected
            conn.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: " + accept.encode() + b"\r\n\r\n")

            if self.push_first:
                # A server that starts talking before being asked.
                payload = b"welcome"
                conn.sendall(bytes([0x81, len(payload)]) + payload)
            # Read whatever the client sends, then close.
            conn.settimeout(3.0)
            try:
                while True:
                    if not conn.recv(4096):
                        break
            except OSError:
                pass
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def _serve(handler):
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _open_ws(push_first=True, **kw):
    """A server that accepts anyone, by default pushing before being asked."""
    cls = type("H", (_WSHandler,),
               dict(require_auth=False, push_first=push_first, **kw))
    return _serve(cls)


def _locked_ws():
    """A server that refuses an unauthenticated upgrade."""
    cls = type("H", (_WSHandler,), dict(require_auth=True, push_first=False))
    return _serve(cls)


def _delayed_push_socket():
    """A server whose greeting arrives in its own segment, after the handshake.

    Same behaviour as the pushing fixture, but the two writes are separated by a
    pause, so the client cannot receive them in a single read.
    """
    class _Slow(_WSHandler):
        def handle(self):
            conn = self.request
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            head, _, _ = buf.partition(b"\r\n\r\n")
            headers = {}
            for line in head.decode("latin-1").split("\r\n")[1:]:
                if ":" in line:
                    name, _, value = line.partition(":")
                    headers[name.strip().lower()] = value.strip()
            key = headers.get("sec-websocket-key", "")
            accept = base64.b64encode(
                hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
            conn.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: " + accept.encode() + b"\r\n\r\n")
            time.sleep(0.4)
            conn.sendall(bytes([0x81, 7]) + b"welcome")
            conn.settimeout(3.0)
            try:
                while conn.recv(4096):
                    pass
            except OSError:
                pass

    srv, port = _serve(_Slow)
    return srv, f"http://127.0.0.1:{port}/ws"


@pytest.fixture
def open_socket():
    srv, port = _open_ws()
    try:
        yield f"http://127.0.0.1:{port}/ws"
    finally:
        srv.shutdown()


@pytest.fixture
def quiet_open_socket():
    """Accepts anyone but says nothing until spoken to."""
    srv, port = _open_ws(push_first=False)
    try:
        yield f"http://127.0.0.1:{port}/ws"
    finally:
        srv.shutdown()


@pytest.fixture
def bad_accept_socket():
    srv, port = _open_ws(bad_accept=True)
    try:
        yield f"http://127.0.0.1:{port}/ws"
    finally:
        srv.shutdown()


@pytest.fixture
def locked_socket():
    srv, port = _locked_ws()
    try:
        yield f"http://127.0.0.1:{port}/ws"
    finally:
        srv.shutdown()


# --------------------------------------------------------------------------
# Framing
# --------------------------------------------------------------------------

class TestWebSocketFraming:
    def test_accept_matches_the_rfc_example(self):
        """RFC 6455 section 1.3's worked example, so the digest is pinned."""
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        assert HttpProbeServer._ws_accept_for(key) == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

    def test_client_frames_are_masked(self):
        """RFC 6455 requires clients to mask; an unmasked frame is not conformant."""
        frame = HttpProbeServer._ws_encode_frame(b"hello")
        assert frame[1] & 0x80, "mask bit must be set on a client frame"
        assert frame[0] & 0x80, "FIN must be set"
        assert frame[0] & 0x0F == 0x1, "opcode must be text"

    def test_masked_payload_round_trips(self):
        payload = b"the quick brown fox"
        frame = HttpProbeServer._ws_encode_frame(payload)
        mask = frame[2:6]
        body = frame[6:]
        unmasked = bytes(b ^ mask[i % 4] for i, b in enumerate(body))
        assert unmasked == payload

    def test_long_payload_uses_an_extended_length(self):
        frame = HttpProbeServer._ws_encode_frame(b"x" * 300)
        assert frame[1] & 0x7F == 126
        assert int.from_bytes(frame[2:4], "big") == 300


# --------------------------------------------------------------------------
# Bounds
# --------------------------------------------------------------------------

class TestWebSocketBounds:
    def test_handshake_headers_are_not_settable(self):
        for name in ("Upgrade", "Sec-WebSocket-Key", "Sec-WebSocket-Version",
                     "Sec-WebSocket-Accept", "Connection", "Host",
                     "Content-Length", "Transfer-Encoding"):
            assert name.lower() in BLOCKED_WEBSOCKET_HEADERS, name

    def test_subprotocol_is_settable_because_it_selects_auth(self):
        """A server that authenticates via a chosen subprotocol needs this."""
        srv = HttpProbeServer()
        out = srv._validate_websocket_headers({"Sec-WebSocket-Protocol": "auth.v1"})
        assert out == {"Sec-WebSocket-Protocol": "auth.v1"}

    def test_upgrade_cannot_be_faked(self):
        srv = HttpProbeServer()
        with pytest.raises(ValueError, match="WebSocket handshake"):
            srv._validate_websocket_headers({"Upgrade": "websocket"})

    def test_error_names_the_reason_rather_than_blaming_the_client(self):
        """The generic message would be wrong here: no HTTP client is involved."""
        srv = HttpProbeServer()
        with pytest.raises(ValueError, match="defines the WebSocket handshake"):
            srv._validate_websocket_headers({"Sec-WebSocket-Key": "abc"})

    def test_smuggling_error_names_framing(self):
        srv = HttpProbeServer()
        with pytest.raises(ValueError, match="framing or routing"):
            srv._validate_smuggle_headers({"Transfer-Encoding": "chunked"})

    def test_caller_cannot_choose_the_ambiguous_length(self):
        """The tool owns both framing headers, or the variant means nothing."""
        srv = HttpProbeServer()
        for name in ("Content-Length", "Transfer-Encoding"):
            with pytest.raises(ValueError):
                srv._validate_smuggle_headers({name: "0"})

    def test_arbitrary_headers_still_pass(self):
        srv = HttpProbeServer()
        assert srv._validate_websocket_headers({"X-Tenant": "acme"}) == {"X-Tenant": "acme"}

    def test_header_injection_is_blocked(self):
        srv = HttpProbeServer()
        with pytest.raises(ValueError, match="newlines"):
            srv._validate_websocket_headers({"X-A": "1\r\nInjected: 2"})

    async def test_timeout_must_be_a_number(self):
        srv = HttpProbeServer()
        with pytest.raises(ValueError, match="timeout"):
            await srv.websocket_auth("http://a.test/", timeout="soon")

    async def test_message_must_be_a_string(self):
        srv = HttpProbeServer()
        with pytest.raises(ValueError, match="string"):
            await srv.websocket_auth("http://a.test/", message={"a": 1})


# --------------------------------------------------------------------------
# The verdict
# --------------------------------------------------------------------------

class TestWebSocketVerdict:
    async def test_flags_an_open_upgrade_that_pushes_first(self, open_socket):
        srv = HttpProbeServer()
        result = await srv.websocket_auth(open_socket)
        assert isinstance(result, ProbeWebSocketAuth)
        assert result.upgrade_granted is True
        assert result.accept_valid is True
        assert WS_FINDING_UNAUTHENTICATED_UPGRADE in result.findings
        assert WS_FINDING_DATA_BEFORE_AUTH in result.findings
        assert result.data_before_client_message is True
        assert result.frames, "the server's greeting should be captured"
        assert result.frames[0].payload_preview == "welcome"

    async def test_a_quiet_but_open_upgrade_is_still_flagged(self, quiet_open_socket):
        """Accepting anyone is the finding; whether it then talks is detail."""
        srv = HttpProbeServer()
        result = await srv.websocket_auth(quiet_open_socket)
        assert result.upgrade_granted is True
        assert WS_FINDING_UNAUTHENTICATED_UPGRADE in result.findings
        assert result.data_before_client_message is False

    async def test_flags_a_wrong_accept_header(self, bad_accept_socket):
        """The cross-site hijacking condition: the reply is not bound to us."""
        srv = HttpProbeServer()
        result = await srv.websocket_auth(bad_accept_socket)
        assert result.upgrade_granted is True
        assert result.accept_valid is False
        assert WS_FINDING_ACCEPT_NOT_VALIDATED in result.findings

    async def test_a_refused_upgrade_is_not_a_finding_against_the_app(self, locked_socket):
        srv = HttpProbeServer()
        result = await srv.websocket_auth(locked_socket)
        assert result.upgrade_granted is False
        assert result.handshake_status == 401
        assert result.findings == [WS_FINDING_UPGRADE_REJECTED]
        assert "did check the request" in result.note

    async def test_an_authenticated_upgrade_is_not_called_unauthenticated(self, locked_socket):
        """The same endpoint, with a session. The label, not a 401."""
        srv = HttpProbeServer()
        identities = [{"label": "tester", "headers": {"Authorization": "Bearer jwt-value"}}]
        result = await srv.websocket_auth(
            locked_socket, identities=identities, identity="tester")
        assert result.upgrade_granted is True
        assert WS_FINDING_UNAUTHENTICATED_UPGRADE not in result.findings
        assert result.identity == "tester"

    async def test_dead_port_is_reported_not_raised(self):
        srv = HttpProbeServer()
        result = await srv.websocket_auth("http://127.0.0.1:9/ws")
        assert result.upgrade_granted is False
        assert "could not open a connection" in result.note
        assert result.findings == [WS_FINDING_UPGRADE_REJECTED]

    @pytest.mark.parametrize("header", ["Authorization", "Cookie", "X-Api-Key"])
    async def test_a_credential_cannot_enter_through_the_header_bag(
        self, locked_socket, header
    ):
        """The run is recorded as anonymous, so it must actually be anonymous.

        Otherwise a token attached by an unrelated caller would be sent with a
        record that still says "no credentials", which is exactly the shape of a
        false finding.
        """
        srv = HttpProbeServer()
        with pytest.raises(ValueError, match="identity must be declared"):
            await srv.websocket_auth(
                locked_socket, headers={header: "Bearer jwt-value"})

    async def test_ordinary_headers_are_still_accepted(self, open_socket):
        """Blocking credentials must not turn the tool into a header blacklist."""
        srv = HttpProbeServer()
        result = await srv.websocket_auth(
            open_socket,
            headers={"Sec-WebSocket-Protocol": "wamp", "User-Agent": "t/1"})
        assert result.upgrade_granted is True

    async def test_credential_never_appears_in_the_evidence(self, locked_socket):
        """A socket finding still has to be safe to paste into a report."""
        srv = HttpProbeServer()
        identities = [{"label": "tester", "headers": {"Authorization": "Bearer jwt-value"}}]
        result = await srv.websocket_auth(
            locked_socket, identities=identities, identity="tester")
        assert "jwt-value" not in result.model_dump_json()

    async def test_a_late_push_is_still_an_unsolicited_push(self):
        """The finding must not depend on how TCP happened to segment the reply.

        A server that writes its handshake and greeting as two separate sends is
        just as unauthenticated as one that coalesces them. Deciding the finding
        from the segment boundary would make the same endpoint report or not
        report depending on the network, which is the kind of flake that becomes
        a missed finding in the field.
        """
        fixture_srv, url = _delayed_push_socket()
        srv = HttpProbeServer()
        try:
            result = await srv.websocket_auth(url, timeout=8.0)
            assert result.upgrade_granted is True
            assert result.frames, "the greeting never arrived"
            assert WS_FINDING_DATA_BEFORE_AUTH in result.findings
            assert result.data_before_client_message is True
        finally:
            fixture_srv.shutdown()

    async def test_a_credential_refusal_is_reported_as_a_refusal(self):
        """A refused argument must be a 400, not a 500 that reads as an outage."""
        from mcp_servers.main import _is_rejected_argument

        detail = (
            "Error executing tool http_probe_websocket_auth: Error executing tool "
            "http_probe_websocket_auth: Header 'Authorization' carries a credential; "
            "an identity must be declared as one so the run is recorded as "
            "authenticated rather than anonymous"
        )
        assert _is_rejected_argument(detail) is True, detail

    async def test_findings_are_fixed_strings(self):
        """The runner grades on these, so they must not drift into prose."""
        assert WS_FINDING_UNAUTHENTICATED_UPGRADE == "unauthenticated_upgrade_granted"
        assert WS_FINDING_DATA_BEFORE_AUTH == "data_served_before_any_client_message"
        assert WS_FINDING_ACCEPT_NOT_VALIDATED == "sec_websocket_accept_missing_or_invalid"
        assert WS_FINDING_UPGRADE_REJECTED == "upgrade_rejected"
