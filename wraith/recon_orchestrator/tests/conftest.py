"""Shared fixtures for the recon orchestrator test suite.

``start_session`` reconciles the graph scope against the active runner's ROE
rules before it will scan anything. That gate is a separate concern from most of
this suite, which tests graph-scope matching, so by default reconciliation is
stubbed to agree and those tests keep testing what they mean to test.

Tests that exercise the gate itself ask for ``real_reconcile`` to put the actual
comparison back, together with ``roe_scope_override`` / ``roe_unreachable`` to
control what the runner reports.
"""
import pytest


class _AgreeReconcile:
    """Stands in for reconcile() with an always-agreeing result."""

    def __call__(self, graph_scope, roe_scope, matcher=None):
        from app.scope_sync import ScopeReconciliation

        return ScopeReconciliation(
            graph_scope=list(graph_scope or []),
            roe_scope=list(roe_scope or []),
            unauthorized=[],
        )


@pytest.fixture(autouse=True)
def agreeing_reconcile(monkeypatch):
    """By default the gate passes: no runner in unit tests, scope assumed agreed.

    Both halves are stubbed -- the fetch would otherwise attempt real HTTP, and
    the comparison would flag everything because there are no ROE rules.
    """
    import app.orchestrator as orchestrator

    monkeypatch.setattr(orchestrator, "reconcile", _AgreeReconcile())
    monkeypatch.setattr(orchestrator, "fetch_roe_rules", _FakeFetch({"scope": [], "aggressive": [], "reachable": True}))


@pytest.fixture
def real_reconcile(monkeypatch):
    """Restore the genuine reconciliation gate for tests that target it."""
    import app.orchestrator as orchestrator
    import app.scope_sync as sync

    monkeypatch.setattr(orchestrator, "reconcile", sync.reconcile)
    return orchestrator


@pytest.fixture
def roe_state(monkeypatch):
    """Control what the active runner reports for the enforced scope.

    ``scope`` lists the enforced patterns; ``aggressive`` lists the subset
    registered with ``allow_aggressive=True`` (patterns are matchable by both,
    ``_FakeFetch`` marks the aggressive ones on their rule objects).
    """
    import app.orchestrator as orchestrator

    state = {"scope": [], "aggressive": [], "reachable": True}
    monkeypatch.setattr(orchestrator, "fetch_roe_rules", _FakeFetch(state))
    return state


@pytest.fixture
def roe_scope_override(roe_state):
    def _set(scope):
        roe_state["scope"] = list(scope)

    return _set


@pytest.fixture
def roe_unreachable(roe_state):
    roe_state["reachable"] = False
    return roe_state


class _FakeFetch:
    def __init__(self, state):
        self._state = state

    async def __call__(self, base_url, investigation_id, token="", **kwargs):
        if not self._state["reachable"]:
            raise RuntimeError("active_exploit_runner unreachable in test")
        aggressive = set(self._state.get("aggressive", []))
        return [
            {
                "pattern": pattern,
                "rule_type": "allow",
                "allow_aggressive": pattern in aggressive,
            }
            for pattern in self._state["scope"]
        ]