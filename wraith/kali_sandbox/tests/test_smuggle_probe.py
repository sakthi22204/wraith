"""Tests for the request-smuggling harness.

The interesting property of this harness is not that it builds an ambiguous
request -- that is arithmetic. It is whether the *verdict* is right, and a
verdict can only be trusted if it has been checked against a target that really
is vulnerable and against one that really is not. So most of this file runs a
two-tier proxy chain in-process, deliberately configured to agree or disagree
about request framing:

  * ``cl_te`` -- the front-end frames by Content-Length, the back-end by
    Transfer-Encoding. This is the classic desync: the back-end stops at the
    empty chunk and serves the hidden request next.
  * ``cl_cl`` -- both hops frame by Content-Length. They agree, so the leftover
    bytes are just body and nothing is smuggled.

A harness that cannot tell those two apart is not measuring anything.
"""
import asyncio
import socket
import socketserver
import threading
import time

import pytest

from mcp_servers.http_probe_server import (
    BLOCKED_SMUGGLE_HEADERS,
    MAX_SMUGGLE_VARIANTS,
    SMUGGLE_VARIANTS,
    HttpProbeServer,
    ProbeSmuggle,
)

pytestmark = pytest.mark.anyio


def asyncio_stub_reader():
    """A reader that yields nothing and then stops, standing in for a socket."""
    class _Reader:
        async def read(self, _n):
            await asyncio.sleep(0)
            return b""
    return _Reader()


# --------------------------------------------------------------------------
# A minimal HTTP/1.1 back-end, with a selectable framing policy.
# --------------------------------------------------------------------------

def _parse_head(head: bytes):
    lines = head.split(b"\r\n")
    parts = lines[0].split()
    if len(parts) < 2:
        return "/", {}, lines
    path = parts[1].decode("latin-1")
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            name, _, value = line.partition(b":")
            headers[name.strip().lower().decode("latin-1")] = value.strip().decode("latin-1")
    return path, headers, lines


def _read_chunked(data: bytes):
    """Return ``(body, leftover)`` or ``None`` if more bytes are needed."""
    out = b""
    i = 0
    while True:
        j = data.find(b"\r\n", i)
        if j == -1:
            return None
        try:
            size = int(data[i:j].split(b";")[0], 16)
        except ValueError:
            return None
        if size == 0:
            end = j + 2
            # The terminating chunk is followed by a final CRLF.
            if len(data) < end + 2:
                return None
            return out, data[end + 2:]
        start = j + 2
        stop = start + size
        if len(data) < stop + 2:
            return None
        out += data[start:stop]
        i = stop + 2


def _respond(conn, path: str, extra: str = "") -> None:
    status = b"200 OK" if path == "/" else b"404 Not Found"
    body = b"ok" if path == "/" else b"not found"
    conn.sendall(
        b"HTTP/1.1 " + status + b"\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        + (extra.encode() if extra else b"")
        + b"Connection: keep-alive\r\n\r\n" + body
    )


class _Backend(socketserver.BaseRequestHandler):
    """Reads requests using one framing policy and leaves the rest queued.

    Leaving the leftover bytes in the buffer is not a bug here -- it is the whole
    point. A back-end that discards them is not desyncable, and the harness
    should say so.
    """

    policy = "cl"

    def handle(self):
        conn = self.request
        buf = b""
        while True:
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            head, rest = buf.split(b"\r\n\r\n", 1)
            path, headers, _ = _parse_head(head)

            chunked = "chunked" in headers.get("transfer-encoding", "").lower()
            if chunked and self.policy == "te":
                parsed = _read_chunked(rest)
                while parsed is None:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    rest += chunk
                    parsed = _read_chunked(rest)
                _, rest = parsed
            else:
                try:
                    length = int(headers.get("content-length", "0"))
                except ValueError:
                    length = 0
                while len(rest) < length:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    rest += chunk
                rest = rest[length:]

            buf = rest
            try:
                _respond(conn, path)
            except OSError:
                return


class _Frontend(socketserver.BaseRequestHandler):
    """Frames the client's request by Content-Length, then relays raw bytes.

    Forwarding exactly the bytes Content-Length covers -- including the hidden
    request -- is the desync. A hardened front-end would instead discard the
    leftover, and the back-end would never see it.

    ``relay_delay`` puts a pause in front of the pipelined leftover, so the
    back end's answer to the hidden request arrives *after* the answers to the
    requests the client really sent. That ordering is the case a detector has to
    survive: the extra response is always last, and a reader that stops when it
    has the responses it expected will never see it.
    """

    backend_addr = None
    relay_delay = 0.0

    def handle(self):
        client = self.request
        try:
            upstream = socket.create_connection(self.backend_addr, timeout=10)
        except OSError:
            return
        buf = b""
        try:
            while b"\r\n\r\n" not in buf:
                chunk = client.recv(4096)
                if not chunk:
                    return
                buf += chunk
            head, rest = buf.split(b"\r\n\r\n", 1)
            _, headers, _ = _parse_head(head)
            try:
                length = int(headers.get("content-length", "0"))
            except ValueError:
                length = 0
            while len(rest) < length:
                chunk = client.recv(4096)
                if not chunk:
                    return
                rest += chunk

            upstream.sendall(head + b"\r\n\r\n" + rest[:length])

            # Whatever the client pipelined after the framed request has to go
            # upstream too. A proxy that dropped it would silently stop being
            # vulnerable, and the harness would report a false negative.
            pending = rest[length:]

            def pump_back():
                try:
                    while True:
                        data = upstream.recv(4096)
                        if not data:
                            break
                        client.sendall(data)
                except OSError:
                    pass

            thread = threading.Thread(target=pump_back, daemon=True)
            thread.start()
            if pending:
                if self.relay_delay:
                    time.sleep(self.relay_delay)
                upstream.sendall(pending)
            while True:
                data = client.recv(4096)
                if not data:
                    break
                upstream.sendall(data)
        except OSError:
            pass
        finally:
            try:
                upstream.close()
            except OSError:
                pass


def _serve(handler_cls):
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler_cls)
    srv.daemon_threads = True
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, srv.server_address[1]


@pytest.fixture
def vulnerable_chain():
    """Front-end on Content-Length, back-end on Transfer-Encoding."""
    backend = type("B", (_Backend,), {"policy": "te"})
    front = type("F", (_Frontend,), {})
    back_srv, back_port = _serve(backend)
    front.backend_addr = ("127.0.0.1", back_port)
    front_srv, front_port = _serve(front)
    try:
        yield f"http://127.0.0.1:{front_port}/"
    finally:
        front_srv.shutdown()
        back_srv.shutdown()


@pytest.fixture
def delayed_chain():
    """A vulnerable chain whose extra response is the last one to arrive.

    Same disagreement as ``vulnerable_chain``, but the front end relays the
    pipelined leftover after a pause. The three responses then come back
    two-then-one rather than all at once, which is what a slower real target
    looks like.
    """
    backend = type("B", (_Backend,), {"policy": "te"})
    front = type("F", (_Frontend,), {"relay_delay": 0.5})
    back_srv, back_port = _serve(backend)
    front.backend_addr = ("127.0.0.1", back_port)
    front_srv, front_port = _serve(front)
    try:
        yield f"http://127.0.0.1:{front_port}/"
    finally:
        front_srv.shutdown()
        back_srv.shutdown()


@pytest.fixture
def consistent_chain():
    """Both hops on Content-Length: they agree, so nothing is smuggled."""
    backend = type("B", (_Backend,), {"policy": "cl"})
    front = type("F", (_Frontend,), {})
    back_srv, back_port = _serve(backend)
    front.backend_addr = ("127.0.0.1", back_port)
    front_srv, front_port = _serve(front)
    try:
        yield f"http://127.0.0.1:{front_port}/"
    finally:
        front_srv.shutdown()
        back_srv.shutdown()


# --------------------------------------------------------------------------
# Bounds and refusal
# --------------------------------------------------------------------------

class TestSmuggleBounds:
    def test_only_the_two_known_pairs_are_offered(self):
        """An open-ended 'send these bytes' mode would be a desync gun."""
        assert set(SMUGGLE_VARIANTS) == {"cl_te", "te_cl"}
        assert MAX_SMUGGLE_VARIANTS == 2

    async def test_unknown_variant_is_refused(self):
        srv = HttpProbeServer()
        with pytest.raises(ValueError, match="cl_te"):
            await srv.smuggle("http://a.test/", variant="raw_bytes")

    def test_host_cannot_be_overridden(self):
        """The hidden request's Host is what keeps a desync on this origin."""
        assert "host" in BLOCKED_SMUGGLE_HEADERS
        srv = HttpProbeServer()
        with pytest.raises(ValueError, match="framing or routing"):
            srv._validate_smuggle_headers({"Host": "victim.example"})

    def test_other_routing_headers_are_refused(self):
        srv = HttpProbeServer()
        for name in ("Connection", "Upgrade", "Transfer-Encoding"):
            with pytest.raises(ValueError):
                srv._validate_smuggle_headers({name: "x"})

    def test_framing_is_not_blocked_by_the_generic_validator(self):
        """Content-Length must be settable here, unlike in http_probe."""
        srv = HttpProbeServer()
        assert srv._validate_smuggle_headers({"X-Trace": "1"}) == {"X-Trace": "1"}

    def test_header_injection_is_still_blocked(self):
        srv = HttpProbeServer()
        with pytest.raises(ValueError, match="newlines"):
            srv._validate_smuggle_headers({"X-A": "1\r\nEvil: 2"})

    async def test_timeout_must_be_a_number(self):
        srv = HttpProbeServer()
        with pytest.raises(ValueError, match="timeout"):
            await srv.smuggle("http://a.test/", timeout="soon")

    async def test_timeout_is_clamped_to_a_ceiling(self):
        """A huge timeout would be a way to hold a connection open."""
        srv = HttpProbeServer()
        result = await srv.smuggle("http://127.0.0.1:9/", variant="cl_te", timeout=10_000)
        assert result.desync_detected is False

    def test_two_requests_are_written_per_variant(self):
        srv = HttpProbeServer()
        wire = srv._smuggle_exchange(
            "POST", "/x", "a.test:80", "cl_te", "/canary", {})
        # Two we write, plus the hidden one the target may end up serving.
        assert wire.count("HTTP/1.1") == 3

    def test_budget_counts_what_the_target_receives(self):
        """Undercounting here would let a sweep slip past the rate limiter."""
        from mcp_servers.http_probe_server import (
            SMUGGLE_REQUESTS_RECEIVED_PER_VARIANT,
            SMUGGLE_REQUESTS_SENT_PER_VARIANT,
        )
        assert SMUGGLE_REQUESTS_SENT_PER_VARIANT == 2
        assert SMUGGLE_REQUESTS_RECEIVED_PER_VARIANT == 3


# --------------------------------------------------------------------------
# Byte construction
# --------------------------------------------------------------------------

class TestSmuggleBytes:
    @staticmethod
    def _declared_cl(wire: str) -> int:
        line = [l for l in wire.split("\r\n") if l.lower().startswith("content-length")][0]
        return int(line.split(":")[1])

    def test_cl_te_advertises_a_length_covering_the_hidden_request(self):
        """Front-end trusts CL, so CL has to cover the hidden request too.

        That is what makes the front-end forward bytes the back-end, reading
        Transfer-Encoding, will stop short of.
        """
        srv = HttpProbeServer()
        canary, authority = "/api/canary", "a.test:80"
        wire = srv._smuggle_exchange("POST", "/api", authority, "cl_te", canary, {})
        hidden = f"GET {canary} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
        assert self._declared_cl(wire) == len("0\r\n\r\n") + len(hidden)

    def test_te_cl_advertises_only_the_hidden_request(self):
        """The reverse pair: CL is short, so a front-end trusting CL drops the
        hidden request while one trusting TE forwards the terminator only."""
        srv = HttpProbeServer()
        canary, authority = "/api/canary", "a.test:80"
        wire = srv._smuggle_exchange("POST", "/api", authority, "te_cl", canary, {})
        hidden = f"GET {canary} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
        assert self._declared_cl(wire) == len(hidden)

    def test_hidden_request_always_targets_the_same_authority(self):
        srv = HttpProbeServer()
        for variant in SMUGGLE_VARIANTS:
            wire = srv._smuggle_exchange(
                "POST", "/api", "target.test:8080", variant, "/api/canary", {})
            hidden = wire.split("0\r\n\r\n", 1)[1]
            assert "Host: target.test:8080" in hidden
            assert "victim" not in hidden

    def test_canary_path_is_unique_per_attempt(self):
        srv = HttpProbeServer()
        one = srv._smuggle_canary_path("/api", "aaaaaa")
        two = srv._smuggle_canary_path("/api", "bbbbbb")
        assert one != two
        assert one.startswith("/api/")

    def test_canary_stays_on_the_requested_origin_path(self):
        srv = HttpProbeServer()
        assert srv._smuggle_canary_path("/", "abc").startswith("/")
        assert "://" not in srv._smuggle_canary_path("/api", "abc")


# --------------------------------------------------------------------------
# The verdict, against a target that is really vulnerable
# --------------------------------------------------------------------------

class TestSmuggleVerdict:
    async def test_detects_a_cl_te_desync(self, vulnerable_chain):
        srv = HttpProbeServer()
        result = await srv.smuggle(vulnerable_chain, variant="cl_te")
        assert isinstance(result, ProbeSmuggle)
        assert result.desync_detected is True
        attempt = result.attempts[0]
        assert attempt.split_detected is True
        # We sent two requests and got three answers. The extra one is the canary.
        assert attempt.requests_sent == 2
        assert attempt.responses_received == 3
        assert attempt.canary_served is True
        assert 404 in attempt.statuses
        # Budgeted by what the target received, not just what we wrote.
        assert result.total_requests == 3

    async def test_detects_a_desync_whose_extra_response_arrives_last(self, delayed_chain):
        """The extra response is always last; a reader must not stop before it.

        A detector that returns as soon as it has the responses it expected
        would find this chain clean, and would find the same chain vulnerable on
        a faster run. That is not a flake to shrug at: it is a real desync being
        reported as a clean exchange, and it is the answer this tool exists to
        produce.
        """
        srv = HttpProbeServer()
        result = await srv.smuggle(delayed_chain, variant="cl_te", timeout=8.0)
        assert result.desync_detected is True
        attempt = result.attempts[0]
        assert attempt.responses_received == 3
        assert attempt.split_detected is True

    @pytest.mark.parametrize("run", range(6))
    async def test_the_verdict_does_not_depend_on_timing(self, vulnerable_chain, run):
        """Repeated runs must agree, or the result is a coin toss.

        Anything timing-dependent here is a finding that appears intermittently,
        which in a report is indistinguishable from a false positive.
        """
        srv = HttpProbeServer()
        result = await srv.smuggle(vulnerable_chain, variant="cl_te", timeout=8.0)
        assert result.desync_detected is True, f"run {run} missed the desync"
        assert result.attempts[0].responses_received == 3, f"run {run} undercounted"

    async def test_does_not_fire_on_a_consistent_chain(self, consistent_chain):
        """The negative matters as much as the positive."""
        srv = HttpProbeServer()
        result = await srv.smuggle(consistent_chain, variant="cl_te")
        assert result.desync_detected is False
        attempt = result.attempts[0]
        assert attempt.split_detected is False
        assert attempt.responses_received == attempt.requests_sent
        assert 404 not in attempt.statuses

    async def test_a_404_on_the_callers_own_path_is_not_a_desync(self, consistent_chain):
        """Pointed at a missing path, every response is legitimately 404.

        Without the tail check this would report smuggling on every probe of an
        endpoint that does not exist, which is the easiest way to turn a
        security tool into noise.
        """
        missing = consistent_chain.rstrip("/") + "/no-such-path"
        srv = HttpProbeServer()
        result = await srv.smuggle(missing, variant="cl_te")
        assert result.desync_detected is False
        assert result.attempts[0].split_detected is False

    def test_informational_responses_are_not_counted(self):
        """A 100 Continue is an answer to a request, not an extra request.

        Without this, any target that sends ``100 Continue`` would read as
        desyncable on every single probe.
        """
        raw = (b"HTTP/1.1 100 Continue\r\n\r\n"
               b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        assert HttpProbeServer._final_statuses(raw) == [200]

    def test_early_hints_are_not_counted_either(self):
        raw = b"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"
        assert HttpProbeServer._final_statuses(raw) == [204]

    def test_answers_equal_to_requests_is_not_a_desync(self):
        split, canary, _ = HttpProbeServer._smuggle_split([200, 200])
        assert split is False
        assert canary is False

    def test_one_answer_more_than_requests_is_a_desync(self):
        split, _, _ = HttpProbeServer._smuggle_split([200, 200, 200])
        assert split is True

    def test_extra_answers_are_the_verdict(self):
        split, canary, note = HttpProbeServer._smuggle_split([200, 404, 200])
        assert split is True
        assert canary is True
        assert "3 requests it was sent 2" in note

    def test_canary_answered_in_our_place_is_a_desync(self):
        """A front-end that swallows our request and serves the leftover."""
        split, canary, _ = HttpProbeServer._smuggle_split([404, 200])
        assert split is True
        assert canary is True

    def test_matching_404s_are_not_a_desync(self):
        split, canary, _ = HttpProbeServer._smuggle_split([404, 404])
        assert split is False

    async def test_both_variants_are_reported(self, vulnerable_chain):
        srv = HttpProbeServer()
        result = await srv.smuggle(vulnerable_chain, variant="both")
        assert set(result.variants_tried) == {"cl_te", "te_cl"}
        assert len(result.attempts) == 2
        # A te_cl chain built the same way still disagrees on the reverse pair.
        assert result.desync_detected is True

    async def test_a_dead_port_is_reported_not_raised(self):
        """A refused connection is a result, not a crash."""
        srv = HttpProbeServer()
        result = await srv.smuggle("http://127.0.0.1:9/", variant="cl_te")
        assert result.desync_detected is False
        assert "could not open a connection" in result.attempts[0].note

    async def test_evidence_hides_the_identity_token(self, monkeypatch):
        """A smuggle can ride a session, and that session must not be recorded."""
        srv = HttpProbeServer()
        identities = [{"label": "victim", "headers": {"Authorization": "Bearer secret-jwt"}}]
        result = await srv.smuggle(
            "http://127.0.0.1:9/", variant="cl_te", identities=identities, identity="victim")
        preview = result.attempts[0].sent_preview
        assert "secret-jwt" not in preview
        assert result.identity == "victim"

    async def test_identity_header_is_sent_but_only_its_label_is_recorded(self, monkeypatch):
        """Scrubbing must happen after sending, not instead of sending.

        The regression this guards: redacting the finished wire string left
        ``Authorization: Bearer <jwt>`` in the evidence, because the text scrubber
        only knows about JSON and query strings.
        """
        srv = HttpProbeServer()
        written = {}

        class _Writer:
            def write(self, data):
                written["wire"] = data

            async def drain(self):
                return None

            def close(self):
                return None

            async def wait_closed(self):
                return None

        async def fake_open(host, port, ssl=None):
            reader = asyncio_stub_reader()
            return reader, _Writer()

        monkeypatch.setattr(
            "mcp_servers.http_probe_server.asyncio.open_connection", fake_open)
        identities = [{"label": "victim", "headers": {"Authorization": "Bearer secret-jwt"}}]
        result = await srv.smuggle(
            "http://a.test/", variant="cl_te", identities=identities, identity="victim")

        # It really was sent, which is the point of an authenticated smuggle.
        assert b"Bearer secret-jwt" in written["wire"]
        # And it is not in the evidence, in any field.
        blob = result.model_dump_json()
        assert "secret-jwt" not in blob
        assert result.identity == "victim"
        assert result.identities_used == ["victim"]
