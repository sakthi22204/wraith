"""A redirect must not be a way out of scope.

The gate checks every URL in a request body before the tool runs, and the grant
binds a single `host:port`. `follow_redirects` then hands the destination over to
httpx, which walks up to three hops on its own and checks nothing. An in-scope
host that answers `302 Location: http://169.254.169.254/latest/meta-data/` is
enough: the hop is fetched and its body is returned to the caller as evidence.

The runner always sends `follow_redirects: False` today, which is why this has
not fired. That is not a mitigation -- the parameter is caller-controlled on the
sandbox's own API, so anything that can reach the port with a valid grant for an
in-scope host sets it to true. The gate is the boundary, so the gate is where the
hop has to be re-checked.

Per the standing decision: re-validation only, no DNS pinning. A hop is refused
unless its host matches the grant and clears scope again; the runner mints a fresh
grant per request, so this costs nothing legitimate.
"""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from mcp_servers.gate import (
    GateError,
    authorization_context,
    revalidate_hop,
)


class Settings:
    REDIS_URL = "redis://unused:6379/0"
    DATABASE_URL = "postgresql://unused/wraith"
    GATE_SECRET = "test-secret"


ALLOWED = [
    {"pattern": "127.0.0.1", "rule_type": "ALLOW"},
    {"pattern": "juice_shop", "rule_type": "ALLOW"},
    {"pattern": "*", "rule_type": "DENY"},
]


class _NullRedis:
    def __init__(self):
        self.spent = set()

    def sadd(self, key, value):
        if value in self.spent:
            return 0
        self.spent.add(value)
        return 1


def _mint(host: str, nonce: str = "n1", inv: str = "inv-1") -> str:
    import hashlib
    import hmac

    from mcp_servers.gate import _b64e

    payload = {"v": 1, "caller": "active_exploit_runner", "inv": inv,
               "host": host, "cost": 1, "exp": int(time.time()) + 60, "nonce": nonce}
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return f"{_b64e(body)}.{_b64e(hmac.new(b'test-secret', body, hashlib.sha256).digest())}"


@pytest.fixture
def stub_gates(monkeypatch):
    import mcp_servers.gate as gate

    monkeypatch.setattr(gate, "killswitch_active", lambda url: False)
    monkeypatch.setattr(gate, "load_scope_rules", lambda url, inv: ALLOWED)
    monkeypatch.setattr(gate, "_redis_client", lambda url: _NullRedis())
    return gate


@pytest.fixture
def ctx(stub_gates):
    return authorization_context(
        caller="active_exploit_runner",
        grant_token=_mint("juice_shop:3000"),
        targets=["http://juice_shop:3000/"],
        settings=Settings,
    )


class TestHopRevalidation:
    def test_a_hop_within_the_grant_is_allowed(self, ctx):
        revalidate_hop(ctx, "http://juice_shop:3000/login")

    def test_a_hop_to_another_host_is_refused(self, ctx):
        """The metadata service, reached through a 302."""
        with pytest.raises(GateError, match="grant is for"):
            revalidate_hop(ctx, "http://169.254.169.254/latest/meta-data/")

    def test_a_hop_to_another_port_is_refused(self, ctx):
        """Same host, different port. The grant binds host *and* port precisely
        so that a grant for the app does not authorise ssh on the same box."""
        with pytest.raises(GateError, match="grant is for"):
            revalidate_hop(ctx, "http://juice_shop:22/")

    def test_a_hop_to_an_out_of_scope_host_is_refused(self, ctx):
        """Even a host the grant names has to clear scope on its own merit."""
        off_rules = dict(ctx, granted_host="other.test:80",
                         rules=[{"pattern": "juice_shop", "rule_type": "ALLOW"},
                                {"pattern": "*", "rule_type": "DENY"}])
        with pytest.raises(GateError, match="does not match any allow rule"):
            revalidate_hop(off_rules, "http://other.test/")

    def test_a_hop_with_no_readable_host_is_refused(self, ctx):
        with pytest.raises(GateError, match="could not determine destination host"):
            revalidate_hop(ctx, "not a url at all")

    def test_a_bare_host_hop_is_checked_against_the_grant(self, ctx):
        """A Location of `juice_shop:3000` has no scheme, and is still a hop.

        It resolves to the same authority as the URL form, so the same grant
        covers it. A bare host with no port resolves to :80, which this grant
        does not name -- so it is refused, and refused on the port rather than
        on a parse failure.
        """
        revalidate_hop(ctx, "juice_shop:3000")

        with pytest.raises(GateError, match="grant is for 'juice_shop:3000'"):
            revalidate_hop(ctx, "juice_shop")

        with pytest.raises(GateError, match="grant is for"):
            revalidate_hop(ctx, "other_host:3000")

    def test_the_context_carries_what_a_hop_needs(self, ctx):
        """Hops are re-checked many times against one already-verified grant.
        Re-running the signature check per hop is wasted work; skipping the
        checks altogether is the bug."""
        assert ctx["granted_host"] == "juice_shop:3000"
        assert ctx["investigation_id"] == "inv-1"
        assert ctx["rules"]
        revalidate_hop(ctx, "http://juice_shop:3000/a")
        revalidate_hop(ctx, "http://juice_shop:3000/b")

    def test_revalidating_a_hop_does_not_spend_the_grant(self, ctx):
        """A 3-hop redirect is one grant. Burning it on the first hop would make
        the second and third hops fail as replays."""
        for _ in range(5):
            revalidate_hop(ctx, "http://juice_shop:3000/next")


@pytest.fixture
def redirect_server():
    """A real 302 to a real second server, so this is not a mock of httpx.

    The point is that the Location header is fully under the target's control --
    that is the whole attack -- so the test has to go through an actual HTTP
    round trip for the assertion to mean anything.
    """
    served = []

    class _Meta(BaseHTTPRequestHandler):
        def do_GET(self):
            served.append(("meta", self.path))
            body = b"AWS_SECRET_ACCESS_KEY=leaked"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    meta = ThreadingHTTPServer(("127.0.0.1", 0), _Meta)
    threading.Thread(target=meta.serve_forever, daemon=True).start()

    class _App(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/start":
                served.append(("app", self.path))
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{meta.server_port}/latest/meta-data/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            served.append(("app", self.path))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    app = ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=app.serve_forever, daemon=True).start()

    yield f"http://127.0.0.1:{app.server_port}/start", served

    meta.shutdown()
    app.shutdown()


class TestProbeRedirects:
    @pytest.mark.asyncio
    async def test_an_off_scope_hop_never_reaches_the_caller(self, stub_gates,
                                                              redirect_server):
        """End to end. The redirect target's body must not appear in the result.

        The grant names the app's own host:port, so revalidating the hop against
        it refuses the metadata server -- and the refusal happens before the
        request, which is what "before any packet is sent" has to mean.
        """
        from mcp_servers.http_probe_server import HttpProbeServer

        start_url, served = redirect_server
        app_port = int(start_url.split(":")[2].split("/")[0])

        # The probe's ContextVar is process-wide and earlier tests in this module
        # left a context in it; clear it so this test exercises the guard it
        # passes explicitly rather than a leftover from elsewhere.
        from mcp_servers.http_probe_server import set_redirect_guard
        set_redirect_guard(None)

        ctx = authorization_context(
            caller="active_exploit_runner",
            grant_token=_mint(f"127.0.0.1:{app_port}"),
            targets=[start_url],
            settings=Settings,
        )
        srv = HttpProbeServer()
        # The metadata server is out of scope by name, so the redirect must be
        # refused on the authority check alone -- no DNS pinning needed.
        ctx["rules"] = [{"pattern": "127.0.0.1", "rule_type": "ALLOW"},
                        {"pattern": "*", "rule_type": "DENY"}]

        with pytest.raises(GateError):
            await srv.probe(start_url, follow_redirects=True, redirect_guard=ctx)

        assert ("meta", "/latest/meta-data/") not in served, (
            "the redirect target was contacted despite being out of scope"
        )

    @pytest.mark.asyncio
    async def test_without_following_redirects_the_302_is_returned_as_evidence(
        self, stub_gates, redirect_server
    ):
        """The default path is unchanged: the 302 itself is the finding, and
        its Location is visible to the analyst."""
        from mcp_servers.http_probe_server import HttpProbeServer

        start_url, _ = redirect_server
        cap = await HttpProbeServer().probe(start_url, follow_redirects=False)
        assert cap.status_code == 302
        assert any("127.0.0.1" in h for h in cap.redirects) or cap.final_url == start_url