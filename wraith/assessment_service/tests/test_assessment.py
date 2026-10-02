import pytest
from app.services import AssessmentEngine

def test_assessment_engine():
    graph_data = {
        "nodes": [
            {"id": "h1", "labels": ["Host"], "properties": {"value": "example.com"}},
            {"id": "s1", "labels": ["Service"], "properties": {"name": "SSH"}},
            {"id": "e1", "labels": ["Endpoint"], "properties": {"url": "/api/v1/admin"}},
            # AI_VALIDATED, because a graph Finding only carries weight once
            # someone proved it. Left statusless this scored 4.0 for a bug that
            # had never been tested.
            {"id": "f1", "labels": ["Finding"], "properties": {"severity": "critical", "status": "AI_VALIDATED"}}
        ],
        "links": [
            {"source": "h1", "target": "e1", "type": "HAS_ENDPOINT"}
        ]
    }

    report = AssessmentEngine.generate_report("inv-123", graph_data)
    assert report.investigation_id == "inv-123"
    assert report.risk_score > 2.0
    assert len(report.prioritized_targets) == 1
    assert report.prioritized_targets[0].host == "example.com"
