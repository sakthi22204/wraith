import pytest
from unittest.mock import AsyncMock, patch
from fastapi import HTTPException
from app.orchestrator import ReconOrchestrator
from app.schemas import ReconRequest

@pytest.mark.asyncio
async def test_start_session_scope_enforcement():
    orchestrator = ReconOrchestrator()

    # Mock graph_client.get_program_scope
    with patch("app.orchestrator.graph_client.get_program_scope", new_callable=AsyncMock) as mock_get_scope:
        mock_get_scope.return_value = ["example.com", "test.org"]

        # 1. Fully in-scope (a literal rule covers exactly the named host)
        request = ReconRequest(program_id="p1", domains=["example.com", "test.org"])
        res = await orchestrator.start_session(request)
        session_id = res["session_id"]
        assert session_id in orchestrator.sessions
        assert orchestrator.sessions[session_id].status == "accepted"

        # 1b. A subdomain is not covered by a literal host rule
        request = ReconRequest(program_id="p1", domains=["sub.example.com"])
        with pytest.raises(HTTPException) as exc:
            await orchestrator.start_session(request)
        assert exc.value.status_code == 400
        assert "sub.example.com" in exc.value.detail

        # 2. Partially out-of-scope
        request = ReconRequest(program_id="p1", domains=["example.com", "malicious.com"])
        with pytest.raises(HTTPException) as exc:
            await orchestrator.start_session(request)
        assert exc.value.status_code == 400
        assert "malicious.com" in exc.value.detail

        # Check session was created with rejected status
        # We need to find the session_id for the rejected session.
        # It's generated inside start_session.
        rejected_sessions = [s for s in orchestrator.sessions.values() if s.status == "rejected"]
        assert rejected_sessions

        # 3. Exactly out-of-scope (subdomain of another but not allowed)
        # e.g. "notexample.com" should not match "example.com"
        request = ReconRequest(program_id="p1", domains=["notexample.com"])
        with pytest.raises(HTTPException) as exc:
            await orchestrator.start_session(request)
        assert "notexample.com" in exc.value.detail

@pytest.mark.asyncio
async def test_parent_domain_of_in_scope_subdomain_is_not_allowed():
    """A literal subdomain rule covers only that host.

    Expanding it to the parent zone would scan a host the program did not list;
    programs that grant subdomains say so with a wildcard.
    """
    orchestrator = ReconOrchestrator()
    with patch("app.orchestrator.graph_client.get_program_scope", new_callable=AsyncMock) as mock_get_scope:
        mock_get_scope.return_value = ["https://www.luminadatamatics.com/"]

        request = ReconRequest(program_id="p1", domains=["luminadatamatics.com", "api.luminadatamatics.com"])
        with pytest.raises(HTTPException) as exc:
            await orchestrator.start_session(request)
        assert exc.value.status_code == 400
        assert "luminadatamatics.com" in exc.value.detail


@pytest.mark.asyncio
async def test_wildcard_scope_authorizes_subdomains():
    """Subdomains are granted explicitly, with wildcard semantics."""
    orchestrator = ReconOrchestrator()
    with patch("app.orchestrator.graph_client.get_program_scope", new_callable=AsyncMock) as mock_get_scope:
        mock_get_scope.return_value = ["*.luminadatamatics.com"]

        request = ReconRequest(
            program_id="p1",
            domains=["www.luminadatamatics.com", "api.luminadatamatics.com"],
        )
        res = await orchestrator.start_session(request)
        assert res["session_id"] in orchestrator.sessions
        assert orchestrator.sessions[res["session_id"]].status == "accepted"

@pytest.mark.asyncio
async def test_grandparent_domain_out_of_scope_after_subdomain():
    """Covering an in-scope subdomain must not grant access to an unrelated or
    root-level domain (e.g. scope www.example.com must not open up 'example' zones)."""
    orchestrator = ReconOrchestrator()
    with patch("app.orchestrator.graph_client.get_program_scope", new_callable=AsyncMock) as mock_get_scope:
        mock_get_scope.return_value = ["www.luminadatamatics.com"]

        request = ReconRequest(program_id="p1", domains=["com"])
        with pytest.raises(HTTPException) as exc:
            await orchestrator.start_session(request)
        assert exc.value.status_code == 400

@pytest.mark.asyncio
async def test_start_session_graph_db_down():
    orchestrator = ReconOrchestrator()
    with patch("app.orchestrator.graph_client.get_program_scope", new_callable=AsyncMock) as mock_get_scope:
        mock_get_scope.side_effect = Exception("GraphDB Down")

        request = ReconRequest(program_id="p1", domains=["example.com"])
        with pytest.raises(HTTPException) as exc:
            await orchestrator.start_session(request)
        assert exc.value.status_code == 400
        assert "Could not fetch program scope" in exc.value.detail


def test_remote_passive_tools_stay_on_the_authorized_host():
    """Bucket enumeration and `-e` JS fetchers reach infrastructure the program
    did not name, so they are not part of passive remote recon."""
    orch = ReconOrchestrator()
    assert "cloud_enum" not in orch.PASSIVE_REMOTE_TOOLS
    assert "linkfinder" not in orch.PASSIVE_REMOTE_TOOLS
    assert "secretfinder" not in orch.PASSIVE_REMOTE_TOOLS
