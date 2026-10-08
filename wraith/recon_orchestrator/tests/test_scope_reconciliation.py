"""The two copies of scope must agree before a scan starts.

Recon selects targets from graph_db's ``scope_domains``; the active runner and
the sandbox independently enforce ``scope_rules`` in postgres. Both records are
needed -- the enforcement copy has to stay independent so a graph compromise
cannot widen what gets sent -- so the fix is a reconciliation gate rather than
one store pointing at the other.
"""
import pytest

from app.scope_sync import (
    ScopeReconciliationError,
    extract_roe_patterns,
    fetch_roe_scope,
    reconcile,
)


def test_matching_scope_is_agreed():
    result = reconcile(["tax.crypto.com"], ["tax.crypto.com"])
    assert result.agreed is True
    assert result.unauthorized == []


def test_graph_scope_absent_from_roe_is_flagged():
    """The drift that made the tax run confusing: graph says one thing, ROE another."""
    result = reconcile(["tax.crypto.com"], ["example.com"])
    assert result.agreed is False
    assert result.unauthorized == ["tax.crypto.com"]


def test_apex_roe_covers_subdomain_consistently_with_runner():
    """Apex-covers-subdomain is the codebase-wide rule, in both copies.

    ROE ``crypto.com`` and graph ``tax.crypto.com`` reconcile as agreeing
    because the runner's own scope check would also permit that host. Tightening
    only this comparison would report drift where the runner has none.
    """
    result = reconcile(["tax.crypto.com"], ["crypto.com"])
    assert result.agreed is True


def test_empty_roe_scope_flags_everything():
    result = reconcile(["tax.crypto.com", "api.tax.crypto.com"], [])
    assert result.agreed is False
    assert set(result.unauthorized) == {"tax.crypto.com", "api.tax.crypto.com"}


def test_wildcard_roe_covers_subdomains():
    result = reconcile(["rpc.testnet.arc.io"], ["*.arc.io"])
    assert result.agreed is True


def test_roe_cannot_widen_graph():
    """Enforcement broader than selection is not drift; recon just selects less."""
    result = reconcile(["a.example.com"], ["example.com", "other.test"])
    assert result.agreed is True


def test_custom_matcher_used():
    result = reconcile(
        ["a.example.com"],
        ["EXAMPLE.COM"],
        matcher=lambda domain, allowed: any(domain.endswith(p) for p in allowed),
    )
    assert result.agreed is True


def test_matcher_receives_normalized_list():
    captured = {}

    def matcher(domain, allowed):
        captured["domain"] = domain
        captured["allowed"] = allowed
        return True

    reconcile(["A.Example.COM"], ["EXAMPLE.COM", "  *.b.io  "], matcher=matcher)
    assert captured["domain"] == "a.example.com"
    assert captured["allowed"] == ["example.com", "*.b.io"]


def test_extract_patterns_from_various_shapes():
    assert extract_roe_patterns([{"pattern": "a.com"}, {"pattern": "b.com"}]) == ["a.com", "b.com"]
    assert extract_roe_patterns(["a.com"]) == ["a.com"]
    assert extract_roe_patterns({"rules": [{"value": "c.com"}]}) == ["c.com"]
    assert extract_roe_patterns(None) == []


def test_extract_rules_normalizes_rule_objects():
    from app.scope_sync import extract_roe_rules

    rules = extract_roe_rules(
        {
            "rules": [
                {"pattern": "a.com", "rule_type": "allow", "allow_aggressive": True},
                {"pattern": "b.com", "rule_type": "allow", "allow_aggressive": False},
                {"pattern": "c.com", "rule_type": "deny"},
            ]
        }
    )
    assert rules == [
        {"pattern": "a.com", "rule_type": "allow", "allow_aggressive": True},
        {"pattern": "b.com", "rule_type": "allow", "allow_aggressive": False},
        {"pattern": "c.com", "rule_type": "deny", "allow_aggressive": False},
    ]
    assert extract_roe_rules(None) == []
    assert extract_roe_rules([]) == []
    # An absent flag reads as False: opt-in is never implicit.
    assert extract_roe_rules([{"pattern": "x.io"}])[0]["allow_aggressive"] is False


def test_extract_patterns_reads_flags_back_out():
    """fetch_roe_scope still returns plain patterns even though the fetch now
    reads rule objects -- reconciliation and matcher tests keep their shape."""
    from app.scope_sync import extract_roe_rules

    patterns = extract_roe_patterns(
        extract_roe_rules(
            [{"pattern": "a.com", "rule_type": "allow", "allow_aggressive": True}]
        )
    )
    assert patterns == ["a.com"]


def test_error_message_names_the_fix():
    err = ScopeReconciliationError(["x.io"], ["x.io"], [])
    assert "x.io" in str(err)
    assert "/roe/scope" in str(err)


@pytest.mark.asyncio
async def test_fetch_roe_scope_reads_runner(monkeypatch):
    import app.scope_sync as sync

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return [{"pattern": "rpc.testnet.arc.io", "rule_type": "DOMAIN"}]

    class FakeClient:
        def __init__(self, *a, **k):
            self.url = None

        async def get(self, url, headers=None):
            self.url = url
            return FakeResponse()

        async def aclose(self):
            return None

    client = FakeClient()
    patterns = await fetch_roe_scope(
        "http://runner:8003/api/v1", "inv-1", token="t", client=client
    )
    assert patterns == ["rpc.testnet.arc.io"]
    assert client.url.endswith("/roe/scope/inv-1")
    assert sync.extract_roe_patterns([]) == []


@pytest.mark.asyncio
async def test_fetch_returns_empty_without_url():
    assert await fetch_roe_scope("", "inv-1") == []


# -- the gate inside start_session ------------------------------------------


@pytest.mark.asyncio
async def test_start_session_rejects_scope_the_runner_does_not_enforce(
    real_reconcile, roe_state, monkeypatch
):
    """The drift this gate exists for, exercised through the real reconciler."""
    from unittest.mock import AsyncMock

    from fastapi import HTTPException

    from app.schemas import ReconRequest

    monkeypatch.setattr(
        real_reconcile.graph_client,
        "get_program_scope",
        AsyncMock(return_value=["tax.crypto.com"]),
    )
    roe_state["scope"] = ["example.com"]

    orch = real_reconcile.ReconOrchestrator()
    with pytest.raises(HTTPException) as exc:
        await orch.start_session(
            ReconRequest(investigation_id="p1", domains=["tax.crypto.com"])
        )

    assert exc.value.status_code == 400
    assert "not covered by any active-exploit-runner ROE rule" in exc.value.detail
    assert "tax.crypto.com" in exc.value.detail
    assert "/roe/scope" in exc.value.detail


@pytest.mark.asyncio
async def test_start_session_proceeds_when_the_two_agree(
    real_reconcile, roe_state, monkeypatch
):
    from unittest.mock import AsyncMock

    from app.schemas import ReconRequest

    monkeypatch.setattr(
        real_reconcile.graph_client,
        "get_program_scope",
        AsyncMock(return_value=["rpc.testnet.arc.io"]),
    )
    roe_state["scope"] = ["rpc.testnet.arc.io"]

    orch = real_reconcile.ReconOrchestrator()
    result = await orch.start_session(
        ReconRequest(investigation_id="p1", domains=["rpc.testnet.arc.io"])
    )
    # The gate let it through: a session was accepted rather than rejected.
    assert result
    assert any(s.investigation_id == "p1" for s in orch.sessions.values())


@pytest.mark.asyncio
async def test_start_session_without_roe_opt_in_keeps_aggressive_closed(
    real_reconcile, roe_state, monkeypatch
):
    """An allow rule without allow_aggressive covers the host and nothing more:
    the session's aggressive allowance stays empty."""
    from unittest.mock import AsyncMock

    from app.schemas import ReconRequest

    monkeypatch.setattr(
        real_reconcile.graph_client,
        "get_program_scope",
        AsyncMock(return_value=["rpc.testnet.arc.io"]),
    )
    roe_state["scope"] = ["rpc.testnet.arc.io"]

    orch = real_reconcile.ReconOrchestrator()
    result = await orch.start_session(
        ReconRequest(investigation_id="p1", domains=["rpc.testnet.arc.io"])
    )
    sid = result["session_id"]
    assert orch._aggressive_rules.get(sid) == []
    # Local targets are exempt by construction; a remote one is not.
    assert orch._aggressive_allowed(sid, "rpc.testnet.arc.io") is False


@pytest.mark.asyncio
async def test_start_session_records_aggressive_allowance(
    real_reconcile, roe_state, monkeypatch
):
    """allow_aggressive=True on the covering rule is what opens the gate."""
    from unittest.mock import AsyncMock

    from app.schemas import ReconRequest

    monkeypatch.setattr(
        real_reconcile.graph_client,
        "get_program_scope",
        AsyncMock(return_value=["rpc.testnet.arc.io"]),
    )
    roe_state["scope"] = ["rpc.testnet.arc.io"]
    roe_state["aggressive"] = ["rpc.testnet.arc.io"]

    orch = real_reconcile.ReconOrchestrator()
    result = await orch.start_session(
        ReconRequest(investigation_id="p1", domains=["rpc.testnet.arc.io"])
    )
    sid = result["session_id"]
    assert orch._aggressive_allowed(sid, "rpc.testnet.arc.io") is True


@pytest.mark.asyncio
async def test_aggressive_allowance_is_apex_scoped_not_blanket(
    real_reconcile, roe_state, monkeypatch
):
    """The opt-in covers only the host (and its subdomains) the rule names;
    another host on the same program is not exempt."""
    from unittest.mock import AsyncMock

    from app.schemas import ReconRequest

    monkeypatch.setattr(
        real_reconcile.graph_client,
        "get_program_scope",
        AsyncMock(return_value=["tax.crypto.com", "other.test"]),
    )
    roe_state["scope"] = ["tax.crypto.com", "other.test"]
    roe_state["aggressive"] = ["tax.crypto.com"]

    orch = real_reconcile.ReconOrchestrator()
    result = await orch.start_session(
        ReconRequest(investigation_id="p1", domains=["tax.crypto.com", "other.test"])
    )
    sid = result["session_id"]
    assert orch._aggressive_allowed(sid, "tax.crypto.com") is True
    assert orch._aggressive_allowed(sid, "other.test") is False


@pytest.mark.asyncio
async def test_start_session_fails_closed_when_runner_is_unreachable(
    real_reconcile, roe_unreachable, monkeypatch
):
    from unittest.mock import AsyncMock

    from fastapi import HTTPException

    from app.schemas import ReconRequest

    monkeypatch.setattr(
        real_reconcile.graph_client,
        "get_program_scope",
        AsyncMock(return_value=["rpc.testnet.arc.io"]),
    )

    orch = real_reconcile.ReconOrchestrator()
    with pytest.raises(HTTPException) as exc:
        await orch.start_session(
            ReconRequest(investigation_id="p1", domains=["rpc.testnet.arc.io"])
        )

    assert exc.value.status_code == 400
    assert "cannot verify" in exc.value.detail

# -- a rule is a host, not a host:port ----------------------------------------
#
# The runner matches scope on the destination host and drops the port
# (``host_of`` -> ``urlparse().hostname``), so ``juice_shop`` already authorizes
# ``http://juice_shop:3000``. Reconciliation that compared the strings verbatim
# reported a disagreement the enforcement record did not have and returned 400,
# which stopped recon before any tool ran.


def test_a_bare_host_rule_covers_a_target_carrying_a_port():
    result = reconcile(["juice_shop:3000"], ["juice_shop"])
    assert result.agreed is True
    assert result.unauthorized == []


def test_a_port_on_the_rule_side_is_also_ignored():
    result = reconcile(["juice_shop"], ["juice_shop:3000"])
    assert result.agreed is True


def test_a_port_does_not_widen_to_another_host():
    result = reconcile(["juice_shop:3000"], ["example.com"])
    assert result.agreed is False
    assert result.unauthorized == ["juice_shop:3000"]


def test_the_reported_name_keeps_the_port():
    """The operator has to see what was actually refused, not the reduced host."""
    result = reconcile(["api.example.com:8443"], ["other.test"])
    assert result.unauthorized == ["api.example.com:8443"]


def test_a_url_shaped_graph_scope_still_reconciles():
    result = reconcile(["http://juice_shop:3000"], ["juice_shop"])
    assert result.agreed is True


def test_a_cidr_rule_is_not_rewritten_by_the_port_reduction():
    result = reconcile(["10.0.0.5"], ["10.0.0.0/8"])
    assert result.agreed is True
    # 10.1.0.5 is inside 10.0.0.0/8 -- a /8 covers the whole second octet.
    assert reconcile(["10.1.0.5"], ["10.0.0.0/8"]).agreed is True
    assert reconcile(["11.1.0.5"], ["10.0.0.0/8"]).agreed is False


def test_a_bare_ipv6_literal_is_not_torn_apart():
    result = reconcile(["fe80::1"], ["fe80::1"])
    assert result.agreed is True


def test_bracketed_ipv6_with_a_port_reconciles():
    result = reconcile(["[2001:db8::1]:8443"], ["2001:db8::1"])
    assert result.agreed is True


def test_a_subdomain_on_a_non_default_port_still_matches_its_parent():
    result = reconcile(["api.example.com:8080"], ["example.com"], matcher=None)
    assert result.agreed is True


def test_an_address_outside_a_cidr_is_still_refused():
    # 10.1.0.5 is inside 10.0.0.0/8; 11.0.0.5 is not.
    result = reconcile(["11.0.0.5"], ["10.0.0.0/8"])
    assert result.agreed is False
    assert result.unauthorized == ["11.0.0.5"]


def test_the_orchestrator_matcher_agrees_on_a_cidr():
    """recon's gate runs with this matcher, so the same question has to get the
    same answer here as in the reconciler."""
    from app.orchestrator import ReconOrchestrator

    orch = ReconOrchestrator()
    assert orch._scope_matches_any("10.0.0.5", ["10.0.0.0/8"]) is True
    assert orch._scope_matches_any("11.0.0.5", ["10.0.0.0/8"]) is False
    assert orch._scope_matches_any("juice_shop:3000", ["juice_shop"]) is False, (
        "the port reduction happens in the reconciler; this matcher is given "
        "already-reduced hosts, so it should not be relied on for that"
    )


def test_the_reconciler_passes_reduced_hosts_to_a_caller_matcher():
    """A caller-supplied matcher sees the same shape the orchestrator passes its
    own predicates, which is what keeps the two interchangeable."""
    seen = {}

    def matcher(domain, allowed):
        seen["domain"] = domain
        seen["allowed"] = allowed
        return domain in allowed

    reconcile(["http://juice_shop:3000/api"], ["juice_shop"], matcher=matcher)
    assert seen["domain"] == "juice_shop", (
        f"the matcher was handed the raw entry: {seen}"
    )
    assert seen["allowed"] == ["juice_shop"]
