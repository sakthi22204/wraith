"""A defense that works must not be reported as a vulnerability.

The differential probe compares a baseline request against perturbed variants.
Before these cases were handled, any difference at all counted as evidence: a
Cloudflare-fronted host that answered a benign request with 301 and a SQL
payload with 403 produced ``material=True``, and the hypothesis "parameter may
alter query results" was satisfied. That is a WAF rejecting the payload --
evidence *against* injection -- so it has to grade as inconclusive instead.
"""
from mcp_servers.common.response_diff import (
    baseline_never_reached_app,
    classify_differential,
    edge_blocked,
    summarize_differential,
)


def _cap(status_code=None, body="", headers=None):
    return {
        "status_code": status_code,
        "response_body": body,
        "response_headers": headers or {},
        "elapsed_ms": 100,
    }


def test_redirect_baseline_is_not_material():
    """The tax.crypto.com case: 301 baseline, 403 to the payload."""
    baseline = _cap(301, "<html>Moving</html>", {"location": "https://tax.crypto.com/"})
    variant = _cap(403, "<html>Access denied</html>", {"cf-ray": "abc"})

    result = classify_differential(baseline, variant)

    assert result["material"] is False
    assert result["blocked"] is True
    assert result["inconclusive"] is True
    assert any("redirect" in r for r in result["blocked_reasons"])


def test_waf_block_page_is_not_material():
    baseline = _cap(200, '{"ok":true}', {"content-type": "application/json"})
    variant = _cap(
        403,
        "<html><title>Attention Required!</title>Cloudflare Ray ID: 8f2</html>",
        {"cf-ray": "8f2"},
    )

    result = classify_differential(baseline, variant)

    assert result["material"] is False
    assert result["blocked"] is True


def test_blocked_summary_does_not_read_as_a_finding():
    baseline = _cap(301, "", {"location": "https://x/"})
    variant = _cap(403, "Access denied", {"cf-ray": "1"})

    summary = summarize_differential(classify_differential(baseline, variant))

    assert summary.startswith("inconclusive:")
    assert "material difference" not in summary


def test_genuine_injection_still_material():
    """A real SQL error surfacing only in the variant must stay evidence."""
    baseline = _cap(200, "no results", {"content-type": "application/json"})
    variant = _cap(500, "SQLSTATE[42P01]: syntax error at or near", {"content-type": "application/json"})

    result = classify_differential(baseline, variant)

    assert result["material"] is True
    assert result["blocked"] is False
    assert any("sql_error" in s for s in result["body"].get("newly_exposed_patterns", []))


def test_403_without_block_page_is_still_comparable():
    """A plain 403 is a real app response; only block pages suppress materiality."""
    baseline = _cap(200, '{"data":[]}', {"content-type": "application/json"})
    variant = _cap(403, '{"error":"forbidden"}', {"content-type": "application/json"})

    result = classify_differential(baseline, variant)

    assert result["blocked"] is False
    assert result["material"] is True


def test_baseline_never_reached_app_reasons():
    assert baseline_never_reached_app(_cap(301, "", {"location": "/x"}))
    assert baseline_never_reached_app(
        _cap(403, "Attention Required! Cloudflare Ray ID: 1")
    )
    assert baseline_never_reached_app(_cap(200, "ok")) is None


def test_edge_blocked_detection():
    assert edge_blocked(_cap(403, "Error code: 1020 Access denied"))
    assert edge_blocked(_cap(403, "", {"cf-mitigated": "challenge"}))
    assert edge_blocked(_cap(403, '{"error":"forbidden"}')) is None