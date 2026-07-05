import pytest
from app.schema import FindingCreate, FindingStatus

@pytest.mark.asyncio
async def test_false_positive_pattern_creation_and_matching(repo, program):
    # Setup host and endpoint
    host = await repo.upsert_host({"value": "example.com"}, program.id)
    endpoint = await repo.upsert_endpoint({"url": "http://example.com/api/users/123", "method": "GET"}, host.id)

    # Create finding
    finding = await repo.create_finding(FindingCreate(
        vuln_type="sqli", severity="high", confidence="0.8",
        status=FindingStatus.AI_VALIDATED, description="Bug",
        target_id=endpoint.id, target_type="endpoint"
    ))

    # Mark as false positive
    await repo.mark_reviewed(finding.id, "false_positive", "Looks like a false positive due to custom WAF")

    # Check if pattern exists
    patterns = await repo.check_known_false_positive_patterns(
        program.id, "sqli", "http://example.com/api/users/456" # Different ID, same pattern
    )

    assert len(patterns) == 1
    assert patterns[0].endpoint_pattern == "http://example.com/api/users/{id}"
    assert "WAF" in patterns[0].reason

@pytest.mark.asyncio
async def test_false_positive_pattern_matching_with_parameter(repo, program):
    # Setup host and endpoint
    host = await repo.upsert_host({"value": "test.com"}, program.id)
    endpoint = await repo.upsert_endpoint({"url": "https://test.com/search", "method": "POST"}, host.id)
    param = await repo.upsert_parameter({"name": "q", "location": "query", "param_type": "string"}, endpoint.id)

    # Create finding on parameter
    finding = await repo.create_finding(FindingCreate(
        vuln_type="xss", severity="medium", confidence="0.7",
        status=FindingStatus.AI_VALIDATED, description="XSS in q",
        target_id=param.id, target_type="parameter"
    ))

    # Mark as false positive
    await repo.mark_reviewed(finding.id, "false_positive", "Reflection is sanitized")

    # Check matching
    patterns = await repo.check_known_false_positive_patterns(
        program.id, "xss", "https://test.com/search", "q"
    )
    assert len(patterns) == 1
    assert patterns[0].parameter_name == "q"

    # Check NOT matching different parameter
    patterns2 = await repo.check_known_false_positive_patterns(
        program.id, "xss", "https://test.com/search", "other"
    )
    assert len(patterns2) == 0
