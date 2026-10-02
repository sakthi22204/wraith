"""A port claim must name the ports the tool dials, and only those.

The gap this closes is the one Phase 2 introduced and then left half-wired. The
sandbox had a port-claim parser, a `port_claim` parameter threaded through
`authorization_context`, and a branch in `_check_destination` that used it. But
`_destination_of` returned `None` unconditionally, so nothing ever set it, and
the branch that did exist derived the "granted" set *from the request* -- a
request for `1-65535` was checked against `1-65535` and always passed.

The consequence in a running system: `POST /exploit/propose` with
`action=run_nmap_scan`, `target=juice_shop`, no `ports`. The grant is minted for
`juice_shop:80`, the sandbox accepts a `host:port` match, and nmap then sweeps
1-1000. The grant described one port and authorised a thousand.

Both sides parse the claim independently and compare. That redundancy is the
point: the runner says which ports it will dial, the sandbox says which ports it
will permit, and neither has to trust the other's reading.
"""
import pytest

from mcp_servers.gate import GateError, parse_port_spec

# Imported from the vendored copy of the runner's modules rather than
# reimplemented here, and from a *copy* rather than the runner's source tree
# because the two services ship as separate images with separate build contexts
# -- `app.` does not resolve inside the sandbox container.
# `test_runner_copy_in_sync.py` compares that copy against the real module, so
# these tests cannot quietly pass against an encoder that no longer exists.
from tests._runner.authority import normalize_port_claim, PortClaimError
from tests._runner.grant import mint_grant, verify_grant


# ---------------------------------------------------------------- parsing

@pytest.mark.parametrize("spec,expected", [
    ("80", {80}),
    ("80,443", {80, 443}),
    ("1-5", {1, 2, 3, 4, 5}),
    (" 80 , 443 ", {80, 443}),
    ("443,80", {80, 443}),
])
def test_both_sides_expand_a_spec_identically(spec, expected):
    assert parse_port_spec(spec) == expected
    assert set(normalize_port_claim(spec)) == expected


@pytest.mark.parametrize("spec", [
    "", "   ", None, "80,", "abc", "80-", "-80", "5-1", "0", "65536",
    "80,,443", "80-abc", "-", "http", "80;443",
])
def test_both_sides_refuse_a_malformed_claim(spec):
    """Fails closed on either side, for the same inputs.

    A claim only the sandbox can parse is a grant the runner thought it issued;
    one only the runner can parse is a request the sandbox will not understand.
    Either is a reason to refuse rather than guess.
    """
    with pytest.raises(GateError):
        parse_port_spec(spec)
    with pytest.raises(PortClaimError):
        normalize_port_claim(spec)


def test_a_claim_wider_than_the_cap_is_refused_by_both():
    """4096 is the ceiling. nmap's default `1-1000` fits; `1-65535` does not."""
    assert parse_port_spec("1-1000")

    with pytest.raises(GateError, match="more than"):
        parse_port_spec("1-65535")
    with pytest.raises(PortClaimError, match="more than"):
        normalize_port_claim("1-65535")


# ---------------------------------------------------------------- the gap

class _Stub:
    """Records how far a request got, so a refusal can be attributed."""

    def __init__(self):
        self.dialed = None
        self.calls = []

    def __getattr__(self, name):
        async def _call(*args, **kwargs):
            self.calls.append(name)
            self.dialed = (args, kwargs)
            return {}
        return _call


def _minted(secret, *, host, ports=None, inv="inv-1", caller="active_exploit_runner"):
    return mint_grant(secret, caller=caller, investigation_id=inv,
                      host=host, ports=ports, ttl_seconds=60)


def _check(url, *, granted_host, granted_ports, port_claim, rules=None,
           investigation_id="inv-1"):
    from mcp_servers.gate import _check_destination

    _check_destination(
        url,
        granted_host=granted_host,
        rules=rules if rules is not None else [{"pattern": "juice_shop", "rule_type": "allow"}],
        investigation_id=investigation_id,
        port_claim=port_claim,
        granted_ports=granted_ports,
    )


def test_a_grant_for_one_port_does_not_authorise_an_nmap_sweep():
    """The regression, stated directly.

    Grant: `juice_shop:80`, no port claim. Request: nmap's own default sweep of
    1-1000. Before this fix the request's claim was compared against itself, so
    this passed and nmap touched a thousand ports on the strength of a grant for
    one.
    """
    with pytest.raises(GateError, match="authorises ports"):
        _check("juice_shop", granted_host="juice_shop:80", granted_ports=None,
               port_claim="1-1000")


def test_a_grant_that_names_the_range_authorises_exactly_that_range():
    """The honest grant for a sweep names the sweep, and is accepted."""
    _check("juice_shop", granted_host="juice_shop:80",
           granted_ports=set(range(1, 1001)), port_claim="1-1000")


def test_a_grant_naming_fewer_ports_refuses_the_rest_of_the_request():
    """A grant for 80 and 443 does not cover a request that also wants 8080."""
    with pytest.raises(GateError, match="would dial"):
        _check("juice_shop", granted_host="juice_shop:80",
               granted_ports={80, 443}, port_claim="80,443,8080")


def test_a_single_port_tool_is_bound_by_the_grant_authority():
    """The non-port-claim path must not lose the port half of the binding.

    A single-destination tool takes its port from the URL, so the grant's
    `host:port` already says which one is allowed and no separate port set is
    needed. The check here is therefore the same exact-authority match the
    no-port-claim case uses, and a `granted_ports` set on such a grant cannot
    widen it.
    """
    _check("http://juice_shop:443", granted_host="juice_shop:443",
           granted_ports={443}, port_claim=None)

    with pytest.raises(GateError, match="grant is for 'juice_shop:443'"):
        _check("http://juice_shop:8443", granted_host="juice_shop:443",
               granted_ports={443}, port_claim=None)

    # The host half is checked too. This is the branch that used to compare
    # only the port: a port-bearing grant for juice_shop:80 accepted a request
    # to any host on port 80, as long as scope allowed that other host.
    with pytest.raises(GateError, match="grant is for 'juice_shop:80'"):
        _check("http://other_host:80", granted_host="juice_shop:80",
               granted_ports={80}, port_claim=None)


def test_a_tool_with_no_claim_still_requires_an_exact_authority_match():
    with pytest.raises(GateError, match="grant is for"):
        _check("http://juice_shop:3000", granted_host="juice_shop:443",
               granted_ports=None, port_claim=None)