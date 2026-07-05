import pytest
from app.schema import FindingCreate, FindingStatus
from app.repository import generate_id

@pytest.mark.asyncio
async def test_corroboration_transitions(repo, program):
    # Setup host and endpoint
    host = await repo.upsert_host({"value": "example.com"}, program.id)
    endpoint = await repo.upsert_endpoint({"url": "http://example.com/api", "method": "GET"}, host.id)

    # Create an initial finding with AI_VALIDATED status
    finding_data = FindingCreate(
        vuln_type="sqli",
        severity="high",
        confidence="0.8",
        status=FindingStatus.AI_VALIDATED,
        description="Potential SQLi",
        target_id=endpoint.id,
        target_type="endpoint",
        ai_confidence=0.8,
        ai_reasoning="Looks like SQLi",
        corroborating_sources=["source1"]
    )
    finding = await repo.create_finding(finding_data)
    assert finding.status == FindingStatus.AI_VALIDATED

    # Add first corroboration (already has 1 from create, so source2 makes it 2)
    updated_finding = await repo.add_corroboration(finding.id, "source2")
    assert "source2" in updated_finding.corroborating_sources
    assert updated_finding.status == FindingStatus.CORROBORATED

@pytest.mark.asyncio
async def test_terminal_states_not_overridden(repo, program):
    # Setup host and endpoint
    host = await repo.upsert_host({"value": "example.com"}, program.id)
    endpoint = await repo.upsert_endpoint({"url": "http://example.com/api", "method": "GET"}, host.id)

    # Create HUMAN_CONFIRMED finding
    f1 = await repo.create_finding(FindingCreate(
        vuln_type="sqli", severity="high", confidence="1.0",
        status=FindingStatus.HUMAN_CONFIRMED, description="Confirmed",
        target_id=endpoint.id, target_type="endpoint"
    ))

    # Add corroboration
    updated = await repo.add_corroboration(f1.id, "sourceX")
    assert updated.status == FindingStatus.HUMAN_CONFIRMED # Should stay terminal

    # Create FALSE_POSITIVE finding
    f2 = await repo.create_finding(FindingCreate(
        vuln_type="xss", severity="medium", confidence="0.0",
        status=FindingStatus.FALSE_POSITIVE, description="Not real",
        target_id=endpoint.id, target_type="endpoint"
    ))

    # Add corroboration
    updated2 = await repo.add_corroboration(f2.id, "sourceY")
    assert updated2.status == FindingStatus.FALSE_POSITIVE # Should stay terminal
