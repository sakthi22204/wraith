import pytest
from app.orchestrator import normalize_domain, orchestrator
from app.schemas import ReconRequest
from unittest.mock import AsyncMock, patch
from fastapi import HTTPException

def test_normalize_domain():
    assert normalize_domain("https://example.com") == "example.com"
    assert normalize_domain("http://sub.example.com/path") == "sub.example.com"
    assert normalize_domain("EXAMPLE.COM") == "example.com"
    assert normalize_domain("example.com/") == "example.com"

@pytest.mark.asyncio
async def test_scope_normalization():
    request = ReconRequest(
        program_id="prog-1",
        domains=["chyowe.com", "sub.chyowe.com", "notchyowe.com", "chyowe.com.evil.com"]
    )

    # Mock graph_client to return scheme-prefixed scope
    with patch("app.orchestrator.graph_client") as mock_graph:
        mock_graph.get_program_scope = AsyncMock(return_value=["https://chyowe.com"])

        # We expect it to raise HTTPException because of the last two domains
        with pytest.raises(HTTPException) as excinfo:
            await orchestrator.start_session(request)

        assert excinfo.value.status_code == 400
        # The error message should list the out-of-scope domains
        # "notchyowe.com" and "chyowe.com.evil.com" are out of scope.
        # "chyowe.com" and "sub.chyowe.com" should have been accepted if normalization works.
        detail = excinfo.value.detail
        assert "notchyowe.com" in detail
        assert "chyowe.com.evil.com" in detail
        # Use more specific checks to avoid partial matches
        out_of_scope_list = detail.split(": ")[1].split(", ")
        assert "notchyowe.com" in out_of_scope_list
        assert "chyowe.com.evil.com" in out_of_scope_list
        assert "sub.chyowe.com" not in out_of_scope_list
        assert "chyowe.com" not in out_of_scope_list

@pytest.mark.asyncio
async def test_scope_normalization_success():
    request = ReconRequest(
        program_id="prog-1",
        domains=["chyowe.com", "sub.chyowe.com"]
    )

    with patch("app.orchestrator.graph_client") as mock_graph:
        mock_graph.get_program_scope = AsyncMock(return_value=["https://chyowe.com"])
        mock_graph.create_scan_session = AsyncMock(return_value={"id": "session-123"})

        # Should not raise exception
        session_id = await orchestrator.start_session(request)
        assert session_id is not None
        assert orchestrator.sessions[session_id].status == "accepted"
