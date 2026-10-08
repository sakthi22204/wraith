"""Tests for the tools that were not behind the gate.

`GATED_NETWORK_TOOLS` covered the http_probe family only. `run_nmap_scan`,
`run_nuclei_scan`, `run_sqlmap`, `run_hydra` and `run_msf_module` send traffic to
a destination named in the request body and were dispatched on the strength of
`verify_caller` alone -- which reads the caller's own `X-Wraith-Caller` header.
That is the request asserting something about itself, which is the gap the grant
mechanism was built to close.

These tests pin two things:

1. Every tool that sends traffic is in the gated set, so `gate_request` cannot
   quietly return early for one of them.
2. The destination each tool reads out of its body is what gets scope-checked,
   including the two ways a caller could otherwise smuggle a different host --
   the port a raw-socket tool chooses, and a Metasploit option that overrides
   RHOSTS after the server set it.
"""
import pytest

from mcp_servers.main import (
    DANGEROUS_TOOLS,
    GATED_NETWORK_TOOLS,
    _destination_of,
    gate_request,
)


TRAFFIC_SENDING_TOOLS = {
    "run_nmap_scan",
    "run_nuclei_scan",
    "run_sqlmap",
    "run_hydra",
    "run_msf_module",
    "run_arjun",
    "run_dalfox",
    "run_corsy",
    "run_commix",
    "run_ghauri",
    "run_jwt_tool",
    "run_nikto",
    "run_xsstrike",
    "http_probe",
    "http_probe_diff",
    "http_probe_race",
    "http_probe_threshold",
    "http_probe_smuggle",
    "http_probe_websocket_auth",
}


class TestCoverage:
    def test_every_traffic_sending_tool_is_gated(self):
        """The fail-open to guard against is an unlisted tool.

        `gate_request` returns without checking anything for a tool that is not
        in GATED_NETWORK_TOOLS, so a tool missing from this set dispatches on
        its caller's self-asserted identity alone. The test is written against
        what the sandbox actually exposes rather than restating the constant,
        so adding a tool without gating it fails here.
        """
        import inspect

        import mcp_servers.main as main_mod

        exposed = {
            name
            for name, fn in vars(main_mod).items()
            if callable(fn) and getattr(fn, "__mcp_tool__", None)
        }
        # Names differ from tool names for a couple of these.
        aliases = {"http_probe_websocket_auth": "websocket_auth_probe"}
        missing = {
            name
            for name in exposed
            if name in TRAFFIC_SENDING_TOOLS
            and name not in GATED_NETWORK_TOOLS
        }
        assert not missing, f"exposed but ungated: {sorted(missing)}"

    def test_dangerous_tools_are_a_subset_of_gated_tools(self):
        """A 'dangerous' tool that is not gated is gated by nothing.

        `verify_caller` returns early for any tool outside DANGEROUS_TOOLS, so
        membership there is only meaningful alongside the gate.
        """
        assert DANGEROUS_TOOLS <= GATED_NETWORK_TOOLS


class TestDestinationResolution:
    def test_nmap_target_is_read_and_its_port_claim_reported(self):
        targets, ports = _destination_of("run_nmap_scan", {"target": "juice_shop"})
        assert targets == ["juice_shop"]
        # nmap's own default, because the body named no ports. This used to be
        # hardcoded None, which is why a grant for one port authorised a sweep.
        assert ports == "1-1000"

    def test_the_nmap_claim_follows_the_body_and_the_embedded_port(self):
        """Must match what nmap_server will actually run: `embedded or ports`."""
        assert _destination_of(
            "run_nmap_scan", {"target": "juice_shop", "ports": "443"})[1] == "443"
        # An embedded target port wins over the field, as it does in the server.
        assert _destination_of(
            "run_nmap_scan", {"target": "juice_shop:8080", "ports": "1-1000"})[1] == "8080"

    def test_the_nuclei_claim_is_the_port_the_scheme_implies(self):
        """nuclei takes no port parameter, so its port is the scheme's default."""
        assert _destination_of(
            "run_nuclei_scan", {"target": "https://juice_shop"})[1] == "443"
        assert _destination_of(
            "run_nuclei_scan", {"target": "http://juice_shop:8080"})[1] == "8080"
        assert _destination_of(
            "run_nuclei_scan", {"target": "juice_shop"})[1] == "80"

    def test_a_single_destination_tool_reports_no_port_claim(self):
        """Its port comes from the URL, which the authority already binds."""
        for tool, body in (
            ("run_sqlmap", {"url": "http://juice_shop:3000/?id=1"}),
            ("run_hydra", {"target": "juice_shop"}),
            ("run_msf_module", {"module": "aux/x", "target": "juice_shop"}),
        ):
            assert _destination_of(tool, body)[1] is None

    def test_sqlmap_reads_url_not_target(self):
        """sqlmap takes `url`. Reading `target` would scope-check a field the
        tool never sends, and the request body would still carry the real one."""
        targets, ports = _destination_of("run_sqlmap", {"target": "juice_shop",
                                                        "url": "http://evil.test/?id=1"})
        assert targets == ["http://evil.test/?id=1"]
        assert ports is None

    def test_the_web_scanners_read_url_and_report_no_port_claim(self):
        """The Phase 1.9 scanners take a full URL and dial the port it names,
        so like sqlmap they report no port claim -- the authority the grant
        binds already carries the port, and the whole query string is what
        gets scope-checked and sent."""
        url_tools = ("run_arjun", "run_dalfox", "run_corsy", "run_commix",
                     "run_ghauri", "run_nikto", "run_xsstrike")
        for tool in url_tools:
            targets, ports = _destination_of(tool, {"url": "http://juice_shop:3000/?id=1&x=2"})
            assert targets == ["http://juice_shop:3000/?id=1&x=2"], tool
            assert ports is None, tool
            # A target passed in the wrong field must not be read -- that would
            # scope-check a value the tool never sends.
            with pytest.raises(ValueError):
                _destination_of(tool, {"target": "http://juice_shop:3000/"})

    def test_jwt_tool_reads_target_never_the_token(self):
        """jwt_tool sends the token to `target`; the token is data."""
        targets, ports = _destination_of(
            "run_jwt_tool", {"token": "e30.e30.e30", "target": "http://juice_shop:8080/"})
        assert targets == ["http://juice_shop:8080/"]
        assert ports is None
        with pytest.raises(ValueError):
            _destination_of("run_jwt_tool", {"token": "e30.e30.e30"})

    def test_hydra_and_msf_read_target(self):
        assert _destination_of("run_hydra", {"target": "juice_shop"})[0] == ["juice_shop"]
        assert _destination_of(
            "run_msf_module",
            {"module": "aux/x", "target": "juice_shop", "options": {}},
        )[0] == ["juice_shop"]

    def test_msf_options_cannot_override_rhosts(self):
        """The sandbox emits `set RHOSTS <target>; <options>; run`, and msfconsole
        applies `set` left to right -- so an option named RHOSTS would redirect
        the module to a host the gates never saw."""
        with pytest.raises(ValueError, match="redirect the host"):
            _destination_of("run_msf_module", {
                "module": "aux/x", "target": "juice_shop",
                "options": {"RHOSTS": "169.254.169.254"},
            })

    def test_msf_options_without_host_keys_are_fine(self):
        targets, _ = _destination_of("run_msf_module", {
            "module": "aux/x", "target": "juice_shop", "options": {"THREADS": "4"},
        })
        assert targets == ["juice_shop"]

    def test_msf_lhost_options_are_refused(self):
        for key in ("LHOST", "LHOSTS"):
            with pytest.raises(ValueError, match="redirect the host"):
                _destination_of("run_msf_module", {
                    "module": "aux/x", "target": "juice_shop", "options": {key: "10.0.0.1"},
                })

    def test_missing_destination_raises_rather_than_passing_empty(self):
        for tool, body in (
            ("run_nmap_scan", {}),
            ("run_sqlmap", {"url": ""}),
            ("run_hydra", {"target": None}),
            ("run_jwt_tool", {"token": "e30.e30.e30", "target": ""}),
            ("run_unknown_sender", {}),
        ):
            with pytest.raises(ValueError):
                _destination_of(tool, body)

    def test_probe_variants_are_all_included(self):
        """A diff baseline plus variants: every variant is a separate
        destination and each is checked on its own account."""
        urls, ports = _destination_of("http_probe_diff", {
            "url": "http://juice_shop:3000/",
            "variants": [{"url": "http://evil.test/"}, {"url": "http://juice_shop:3000/x"}],
        })
        assert len(urls) == 3
        assert any("evil.test" in u for u in urls)
        assert ports is None


class TestGateRequestRoutesThroughEnforce:
    def test_ungated_body_never_reaches_the_gate(self, monkeypatch):
        """Sanity check on the harness: a tool with no destination and no gate
        should not call the gate at all."""
        called = []
        monkeypatch.setattr(
            "mcp_servers.main.authorization_context",
            lambda **kw: called.append(kw),
        )
        gate_request("list_msf_modules", {"search": "x"})
        assert called == []

    def test_gated_tool_calls_the_gate_with_the_destination(
        self, monkeypatch, settings_stub
    ):
        from fastapi import HTTPException

        called = {}

        def _gate(**kw):
            called.update(kw)
            return {"granted_host": "juice_shop:80", "rules": [], "investigation_id": "i"}

        monkeypatch.setattr("mcp_servers.main.authorization_context", _gate)
        monkeypatch.setattr(
            "mcp_servers.main.get_caller", lambda: "active_exploit_runner"
        )

        class _Req:
            def __init__(self):
                self.headers = {
                    "X-Wraith-Caller": "active_exploit_runner",
                    "X-Wraith-Grant": "tok",
                }

        gate_request("run_nmap_scan", {"target": "juice_shop"}, request=_Req())
        assert called["caller"] == "active_exploit_runner"
        assert called["grant_token"] == "tok"
        assert any("juice_shop" in t for t in called["targets"])

    def test_gate_refusal_becomes_the_gate_status(self, monkeypatch, settings_stub):
        from fastapi import HTTPException

        from mcp_servers.gate import GateError

        def _gate(**kw):
            raise GateError("grant is for 'other'", 403)

        monkeypatch.setattr("mcp_servers.main.authorization_context", _gate)
        monkeypatch.setattr(
            "mcp_servers.main.get_caller", lambda: "active_exploit_runner"
        )

        class _Req:
            def __init__(self):
                self.headers = {
                    "X-Wraith-Caller": "active_exploit_runner",
                    "X-Wraith-Grant": "tok",
                }

        with pytest.raises(HTTPException) as exc:
            gate_request("run_sqlmap", {"url": "http://juice_shop:3000/"}, request=_Req())
        assert exc.value.status_code == 403


@pytest.fixture
def settings_stub(monkeypatch):
    class _S:
        GATE_SECRET = "s"
        REDIS_URL = "redis://x"
        DATABASE_URL = "postgresql://x"
    import mcp_servers.config as cfg
    monkeypatch.setattr(cfg, "settings", _S())
    return _S()