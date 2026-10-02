"""`confidence` must be one type on the node, whichever path wrote it.

`FindingBase.confidence` was `str` and `FindingUpdate.confidence` was `float`.
Neo4j has no property schema, so nothing objected: a create stored the string
"0.8", a later update to the same node stored the float 0.8, and the same
property on the same row held two types depending on which endpoint touched it
last. Each request re-validated its own model on the way out, so reads kept
working and the drift stayed invisible until something read the raw property and
had to guess.

`confidence` is a display label, not a score. Producers send "high", "certain"
and "0.8" interchangeably, and nothing compares it numerically -- the review
queue orders on `ai_confidence`. So it is a string on both paths, and the numeric
score lives in `ai_confidence`, which is a float.

Deliberately not written against a real Neo4j: the assertion that matters is the
type of the value handed to the query, and a stub session captures that without
the testcontainers dependency that keeps the other repository modules out of
`run_tests.sh graph` entirely.
"""

import pytest
from pydantic import ValidationError

from app.repository import Neo4jRepository
from app.schema import Finding, FindingCreate, FindingUpdate


class _Result:
    def __init__(self, record):
        self._record = record

    async def single(self):
        return self._record


class _StubSession:
    """Stands in for an AsyncSession, recording every query and its params.

    `update_finding` reads the node and then writes it, so it asks for two
    results: the current state, then the written one. Both are served from the
    same dict, which is what a real driver would do too.
    """

    def __init__(self, node: dict):
        self.node = node
        self.writes = []

    async def run(self, query, **params):
        if query.strip().upper().startswith("MATCH") and "SET" in query:
            self.writes.append(params)
            self.node.update({k: v for k, v in params.items() if k != "finding_id"})
        return _Result({"f": dict(self.node)})


def _node(confidence):
    return {
        "id": "f-1",
        "title": None,
        "vuln_type": "sqli",
        "severity": "high",
        "confidence": confidence,
        "status": "unconfirmed",
        "description": "test",
        "ai_confidence": 0.8,
        "ai_reasoning": None,
        "corroborating_sources": None,
        "cvss_vector": None,
        "evidence": None,
        "poc_request": None,
        "poc_response": None,
        "expected_result": None,
        "actual_result": None,
        "steps_to_reproduce": None,
        "root_cause": None,
        "impact": None,
        "remediation": None,
        "validation_stage": "NOT_VALIDATED",
        "probe_principal": None,
        "target_id": "e-1",
        "target_type": "endpoint",
        "discovered_at": "2026-01-01T00:00:00Z",
    }


# --- the schema contract ---------------------------------------------------


def _create(confidence):
    return FindingCreate(
        vuln_type="sqli",
        severity="high",
        confidence=confidence,
        status="unconfirmed",
        description="t",
        target_id="e-1",
        target_type="endpoint",
    )


def test_create_and_update_agree_on_the_type():
    """The bug in one assertion: the same field, two types, two models."""
    base = _create("high")
    patch = FindingUpdate(confidence="high")

    assert type(base.confidence) is type(patch.confidence) is str


def test_a_label_is_accepted_on_both_paths():
    for label in ("high", "certain", "0.8"):
        assert _create(label).confidence == label
        assert FindingUpdate(confidence=label).confidence == label


def test_a_raw_float_is_refused_rather_than_coerced():
    """The visible half of the change, pinned on purpose.

    Silently stringifying would have been friendlier, and would also have let a
    caller keep sending the wrong type indefinitely: nothing would ever complain
    that a score and a label were being mixed. Refusing at the boundary means the
    caller finds out at the call that has to change.

    The agent is unaffected -- it already sends `str(confidence)`. A future
    producer holding a 0.0-1.0 score has to say so via ai_confidence, which is a
    float, rather than smuggling a score into a label field.
    """
    with pytest.raises(ValidationError):
        FindingUpdate(confidence=0.95)

    with pytest.raises(ValidationError):
        _create(0.95)


def test_ai_confidence_remains_the_numeric_field():
    """The score still has a home; this fix did not remove one."""
    update = FindingUpdate()
    assert "ai_confidence" not in update.model_fields, (
        "ai_confidence belongs on the create/assessment path, not the evidence patch"
    )
    assert Finding(**_node("high")).ai_confidence == 0.8


# --- what actually reaches the graph ---------------------------------------


@pytest.mark.asyncio
async def test_update_writes_a_string_confidence():
    """The regression: this used to hand Cypher a float."""
    session = _StubSession(_node("0.8"))
    repo = Neo4jRepository(session)

    await repo.update_finding("f-1", FindingUpdate(confidence="0.9"))

    assert len(session.writes) == 1
    written = session.writes[0]["confidence"]
    assert written == "0.9"
    assert isinstance(written, str), f"wrote a {type(written).__name__} to a label field"


@pytest.mark.asyncio
async def test_a_float_on_an_existing_node_does_not_re_type_it():
    """A node created before the change still round-trips as a string.

    Existing rows hold strings, and a patch to one must not quietly turn the
    property into a float -- that is the drift, reached from the other side.
    """
    session = _StubSession(_node("0.8"))
    repo = Neo4jRepository(session)

    await repo.update_finding("f-1", FindingUpdate(title="new title"))

    assert isinstance(session.node["confidence"], str)
    assert session.node["confidence"] == "0.8"
