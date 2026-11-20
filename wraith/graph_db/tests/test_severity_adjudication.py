"""Severity must be settled by evidence, not by how an author feels about it.

Every case here is a way the risk score could be made to lie: a guess filed as
critical, a proven injection filed as low, a bug that needs a session scored the
same as one that needs nothing. The functions are pure so all of it is decided
without a graph.
"""

import pytest

from app.severity import (
    adjudicate_severity,
    severity_ceiling,
    severity_floor,
    explain,
)


def _finding(**over):
    node = {
        "vuln_type": "SQL Injection",
        "severity": "medium",
        "status": "AI_VALIDATED",
        "validation_stage": "IMPACT_CONFIRMED",
        "probe_principal": "unauthenticated",
        "evidence_sources": ["agent_probe", "exploitation"],
    }
    node.update(over)
    return node


class TestUnvalidatedCannotInflate:
    """Nothing executed is never worse than medium.

    The assessment service sums severities, so a caller able to write "critical"
    onto an unvalidated finding could add 2.0 to a risk score with nothing to
    show for it.
    """

    def test_critical_claim_on_an_unexecuted_finding_is_capped(self):
        assert adjudicate_severity(
            _finding(status="UNCONFIRMED", validation_stage="NOT_VALIDATED",
                     severity="critical")
        ) == "medium"

    def test_ceiling_is_medium_until_validated(self):
        assert severity_ceiling(_finding(status="UNCONFIRMED")) == "medium"
        assert severity_ceiling(_finding(status="FALSE_POSITIVE")) == "medium"
        assert severity_ceiling(_finding(status="DUPLICATE")) == "medium"

    def test_every_validated_status_opens_the_ceiling(self):
        for status in ("AI_VALIDATED", "CORROBORATED", "HUMAN_CONFIRMED"):
            assert severity_ceiling(_finding(status=status)) == "critical"

    def test_status_comparison_is_case_insensitive(self):
        """A finding written as 'ai_validated' must not read as unvalidated.

        Statuses arrive from enum members, from JSON and from hand-written
        callers in either case. Comparing one spelling against another silently
        demotes every real finding to the unvalidated ceiling.
        """
        for spelling in ("AI_VALIDATED", "ai_validated", "Ai_Validated"):
            node = _finding(status=spelling, severity="low")
            assert adjudicate_severity(node) == "critical", spelling

    def test_stage_comparison_is_case_insensitive(self):
        """'condition_confirmed' must be read as the rung it is.

        Getting this wrong is invisible: the finding still gets a severity, just
        the severity of something merely reachable.
        """
        for spelling in ("IMPACT_CONFIRMED", "impact_confirmed"):
            node = _finding(validation_stage=spelling, severity="low",
                            probe_principal="reviewer")
            assert severity_floor(node) == "high", spelling


class TestFloorFromEvidence:
    def test_proven_anonymous_injection_is_critical(self):
        assert severity_floor(_finding()) == "critical"

    def test_exploitability_never_exceeds_critical(self):
        assert severity_floor(
            _finding(validation_stage="EXPLOITABILITY_CONFIRMED")
        ) == "critical"

    def test_injection_needing_a_session_is_high_not_critical(self):
        """PR:L versus PR:N. Requiring credentials is a real reduction in blast
        radius, so the same proven injection must not score identically to the
        anonymous one."""
        node = _finding(probe_principal="reviewer")
        assert severity_floor(node) == "high"

    def test_anonymous_lifts_a_lower_tier(self):
        node = _finding(vuln_type="Missing Security Headers")
        assert severity_floor(node) == "high"

    def test_missing_rate_limiting_stops_at_high_not_critical(self):
        """A missing control is a negative observation, not a demonstrated
        consequence. Even unauthenticated, the evidence-derived floor stops at
        high; the top of the scale is reserved for proven impact."""
        node = _finding(vuln_type="Missing Rate Limiting")
        assert severity_floor(node) == "high"

    def test_authenticated_lower_tier_keeps_its_tier(self):
        node = _finding(vuln_type="Missing Security Headers",
                        probe_principal="reviewer")
        assert severity_floor(node) == "medium"

    def test_reachability_alone_is_a_lead_not_a_vulnerability(self):
        """Proving an endpoint answers is not proving the behaviour is wrong, so
        the anonymous bonus must not apply -- 'anyone can reach it' is not
        'anyone can exploit it'."""
        node = _finding(validation_stage="REACHABILITY_CONFIRMED")
        assert severity_floor(node) == "low"

    def test_unmapped_family_carries_no_inherent_weight(self):
        node = _finding(vuln_type="A Family Nobody Classified")
        assert severity_floor(node) == "medium"

    def test_unvalidated_floor_is_inert(self):
        """An unvalidated guess gets no floor to be clamped up to."""
        assert severity_floor(_finding(status="UNCONFIRMED")) == "info"


class TestAuthorBounds:
    def test_author_cannot_understate_proven_impact(self):
        assert adjudicate_severity(_finding(severity="low")) == "critical"

    def test_author_cannot_inflate_an_unvalidated_finding(self):
        """The ceiling that actually binds is the unvalidated one, and it binds
        hardest on the families that would otherwise score highest."""
        node = _finding(vuln_type="SQL Injection", status="UNCONFIRMED",
                        validation_stage="NOT_VALIDATED", severity="critical")
        assert adjudicate_severity(node) == "medium"

    def test_a_validated_finding_may_be_called_critical(self):
        """Once evidence backs it, critical is a legitimate call and the ceiling
        must not quietly cap it."""
        assert adjudicate_severity(
            _finding(vuln_type="SQL Injection", severity="critical")
        ) == "critical"

    def test_author_may_raise_within_the_ceiling(self):
        """Context the evidence does not carry -- an admin-only route, a
        compensating control -- is legitimate grounds to score higher."""
        node = _finding(vuln_type="Missing Security Headers",
                        probe_principal="reviewer", severity="high")
        assert adjudicate_severity(node) == "high"

    def test_missing_claim_falls_back_to_the_floor(self):
        node = _finding(severity=None)
        assert adjudicate_severity(node) == "critical"

    def test_unknown_severity_string_is_treated_as_info_then_floored(self):
        assert adjudicate_severity(_finding(severity="catastrophic")) == "critical"


class TestDeterminism:
    def test_same_node_always_yields_the_same_answer(self):
        node = _finding()
        assert {adjudicate_severity(node) for _ in range(5)} == {"critical"}

    def test_explain_reports_the_band_it_chose_from(self):
        decision = explain(_finding(severity="low"))
        assert decision["claimed"] == "low"
        assert decision["final"] == "critical"
        assert decision["floor"] == "critical"
        assert "SQL Injection" in decision["reason"]


class TestIdempotentReshaping:
    """Re-adjudicating a stored finding must not change it.

    The assessment service and the report generator both read severity straight
    off the node. If a stored severity could still move under them, the same
    finding would score differently on two reads.
    """

    @pytest.mark.parametrize("status", ["UNCONFIRMED", "AI_VALIDATED"])
    @pytest.mark.parametrize("principal", ["unauthenticated", "reviewer", None])
    def test_stored_value_is_a_fixed_point(self, status, principal):
        node = _finding(status=status, probe_principal=principal)
        once = adjudicate_severity(node)
        node["severity"] = once
        assert adjudicate_severity(node) == once

class TestDisclosureFamiliesCarryTheirOwnWeight:
    """"Information Exposure" is a claim about other people's data.

    The family is tiered with authorization failures, so a stack trace or a
    metrics page filed under it floors at critical the moment it is proven
    anonymously. Those disclosures are real but they leak paths, versions and
    operational counters, not records, so they name their own family and stay at
    the unmapped floor. This is the distinction that stopped the Express error
    page on /graphql from being filed critical.
    """

    def test_error_message_disclosure_is_medium_not_critical(self):
        node = _finding(vuln_type="Error Message Disclosure")
        assert severity_floor(node) == "medium"
        assert adjudicate_severity(node) == "medium"

    @pytest.mark.parametrize("family", [
        "Monitoring Endpoint Exposure",
        "API Documentation Exposure",
    ])
    def test_operational_disclosure_stays_at_the_unmapped_floor(self, family):
        node = _finding(vuln_type=family)
        assert severity_floor(node) == "medium"

    def test_personal_or_confidential_exposure_keeps_the_higher_tier(self):
        """The specific families above must not become a loophole: a disclosure
        that really is another user's data is still an authorization failure."""
        assert severity_floor(_finding(vuln_type="Information Exposure")) == "critical"


class TestBooleanBlindInjectionIsStillDatabaseAccess:
    """A quiet confirmation is not a weaker one.

    The boolean-blind oracle proves the payload was evaluated by the query and
    not escaped. That is the same database access an error- or time-based
    confirmation demonstrates; scoring it lower because the response was a 200
    instead of a 500 would grade the evidence, not the bug.
    """

    def test_boolean_blind_confirmation_is_critical_when_anonymous(self):
        node = _finding(vuln_type="SQL Injection (boolean-blind)")
        assert severity_floor(node) == "critical"
        assert adjudicate_severity(node) == "critical"


class TestExecutionAndDisclosureTiers:
    def test_command_injection_weights_like_code_execution(self):
        assert severity_floor(_finding(vuln_type="Command Injection")) == "critical"
        assert severity_floor(
            _finding(vuln_type="Command Injection", probe_principal="reviewer")
        ) == "high"

    def test_path_traversal_is_a_disclosure_not_an_unmapped_family(self):
        assert severity_floor(_finding(vuln_type="Path Traversal")) == "critical"
        assert severity_floor(
            _finding(vuln_type="Path Traversal", probe_principal="reviewer")
        ) == "high"

    def test_browser_markup_classes_score_as_browser_weaknesses(self):
        for name in ("Cross-Site Scripting", "HTML Injection"):
            assert severity_floor(_finding(vuln_type=name)) == "high", name
            assert severity_floor(
                _finding(vuln_type=name, probe_principal="reviewer")) == "medium", name


class TestImpactGate:
    def test_condition_confirmation_cannot_reach_high_or_critical(self):
        node = _finding(validation_stage="CONDITION_CONFIRMED", severity="critical")
        assert severity_floor(node) == "medium"
        assert severity_ceiling(node) == "medium"
        assert adjudicate_severity(node) == "medium"

    def test_reachability_claim_cannot_be_written_critical(self):
        node = _finding(validation_stage="REACHABILITY_CONFIRMED", severity="critical")
        assert severity_floor(node) == "low"
        assert adjudicate_severity(node) == "medium"

    def test_llm_only_proof_stays_unconfirmed(self):
        node = _finding(evidence_sources=["agent_probe", "llm"], severity="critical")
        assert severity_floor(node) == "info"
        assert severity_ceiling(node) == "medium"
        assert adjudicate_severity(node) == "medium"

    def test_empty_source_set_stays_unconfirmed(self):
        node = _finding(evidence_sources=[], severity="critical")
        assert severity_floor(node) == "info"
        assert adjudicate_severity(node) == "medium"

    def test_unknown_source_cannot_open_the_top_of_the_scale(self):
        node = _finding(evidence_sources=["an unnamed assertion"], severity="critical")
        assert severity_ceiling(node) == "medium"
        assert adjudicate_severity(node) == "medium"

    def test_deterministic_harness_impact_can_reach_critical(self):
        node = _finding(evidence_sources=["agent_probe", "exploitation"], severity="critical")
        assert severity_floor(node) == "critical"
        assert severity_ceiling(node) == "critical"
        assert adjudicate_severity(node) == "critical"

    def test_scanner_and_exploit_sources_can_reach_critical(self):
        node = _finding(evidence_sources=["exploitation", "mcp_tool_result_named"])
        assert adjudicate_severity(node) == "critical"

    def test_legacy_finding_without_source_metadata_trusts_the_stage(self):
        node = _finding(evidence_sources=None)
        assert severity_ceiling(node) == "critical"
        assert adjudicate_severity(node) == "critical"

    def test_explain_reports_whether_impact_was_observed(self):
        decision = explain(_finding(validation_stage="CONDITION_CONFIRMED"))
        assert decision["impact_observed"] is False
        assert decision["final"] == "medium"
        assert explain(_finding())["impact_observed"] is True
