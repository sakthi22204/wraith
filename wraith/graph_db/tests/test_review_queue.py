import pytest
from app.schema import FindingCreate, FindingStatus

@pytest.mark.asyncio
async def test_review_queue_filtering_and_sorting(repo, program):
    # Setup host and endpoint
    host = await repo.upsert_host({"value": "example.com"}, program.id)
    endpoint = await repo.upsert_endpoint({"url": "http://example.com/api", "method": "GET"}, host.id)

    # High severity, low confidence (Priority 1)
    await repo.create_finding(FindingCreate(
        vuln_type="sqli", severity="critical", confidence="0.2",
        status=FindingStatus.UNCONFIRMED, description="V1",
        target_id=endpoint.id, target_type="endpoint", ai_confidence=0.2
    ))

    # Low severity, low confidence (Priority 3)
    await repo.create_finding(FindingCreate(
        vuln_type="info", severity="low", confidence="0.1",
        status=FindingStatus.AI_VALIDATED, description="V2",
        target_id=endpoint.id, target_type="endpoint", ai_confidence=0.1
    ))

    # High severity, medium confidence (Priority 2)
    await repo.create_finding(FindingCreate(
        vuln_type="xss", severity="critical", confidence="0.6",
        status=FindingStatus.AI_VALIDATED, description="V3",
        target_id=endpoint.id, target_type="endpoint", ai_confidence=0.6
    ))

    # High confidence (Should NOT be in queue)
    await repo.create_finding(FindingCreate(
        vuln_type="rce", severity="critical", confidence="0.9",
        status=FindingStatus.AI_VALIDATED, description="V4",
        target_id=endpoint.id, target_type="endpoint", ai_confidence=0.9
    ))

    queue = await repo.get_findings_needing_review(program.id, threshold=0.7)

    assert len(queue) == 3
    # Check sorting: critical/0.2, then critical/0.6, then low/0.1
    assert queue[0].vuln_type == "sqli"
    assert queue[1].vuln_type == "xss"
    assert queue[2].vuln_type == "info"
