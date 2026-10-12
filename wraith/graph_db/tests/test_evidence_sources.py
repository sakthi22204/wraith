"""Three-source confirmation: a validated status must rest on real sources.

P = agent_probe (a criterion the AI agent authored), E = exploitation (an
executed exploit), M = mcp_tool_result (a sandbox scanner's result). A single
source is never enough -- an agent's claim is not proof and a scanner hit is a
guess the target happened to answer. The rule is pure, so it is decided here
without a graph.
"""

import pytest

from app.schema import (
    FindingStatus,
    VALIDATED_STATUSES,
    enforce_evidence_sources,
)


def _finding(**over):
    node = {
        "status": "AI_VALIDATED",
        "evidence_sources": ["agent_probe", "exploitation"],
    }
    node.update(over)
    return node


class TestObservedStatuses:
    def test_observation_is_not_a_validated_status(self):
        assert FindingStatus.OBSERVATION.value not in VALIDATED_STATUSES

    def test_observation_has_its_own_identity(self):
        # Distinct from UNCONFIRMED: a negative signal vs a positive one.
        assert FindingStatus.OBSERVATION != FindingStatus.UNCONFIRMED


class TestSourceRule:
    @pytest.mark.parametrize("sources", [
        ["agent_probe", "exploitation"],
        ["agent_probe", "mcp_tool_result"],
        ["exploitation", "mcp_tool_result_named"],
    ])
    def test_sufficient_sets_leave_the_status_alone(self, sources):
        assert enforce_evidence_sources(_finding(evidence_sources=sources)) is None

    @pytest.mark.parametrize("sources", [
        ["agent_probe"],                       # a claim, not proof
        ["exploitation"],                      # an exploit of what, unstated
        ["mcp_tool_result"],                   # a scanner guess
        ["agent_probe", "agent_probe"],        # not two independent sources
        ["exploitation", "mcp_tool_result"],   # M did not name the vuln
    ])
    def test_insufficient_sets_downgrade_to_unconfirmed(self, sources):
        assert enforce_evidence_sources(
            _finding(evidence_sources=sources)
        ) == "UNCONFIRMED"

    def test_it_only_downgrades_never_grants(self):
        # An UNCONFIRMED verdict the runner reached is not re-promoted, even
        # when the sources would permit validation.
        assert enforce_evidence_sources(
            _finding(status="UNCONFIRMED", evidence_sources=["agent_probe", "exploitation"])
        ) is None

    def test_non_validated_statuses_are_untouched(self):
        for status in ("UNCONFIRMED", "OBSERVATION", "FALSE_POSITIVE"):
            assert enforce_evidence_sources(
                _finding(status=status, evidence_sources=["agent_probe"])
            ) is None

    def test_a_patch_without_sources_is_untouched(self):
        # Backward compatibility: callers outside the three-source model keep
        # their existing behaviour.
        assert enforce_evidence_sources({"status": "AI_VALIDATED"}) is None
        assert enforce_evidence_sources(
            {"status": "AI_VALIDATED", "evidence_sources": None}
        ) is None
