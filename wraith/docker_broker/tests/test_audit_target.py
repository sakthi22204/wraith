import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException
from app.proxy import DockerProxy


async def _run_in_thread(func, *args, **kwargs):
    return func(*args, **kwargs)


@pytest.mark.asyncio
async def test_allowed_create_records_image_in_audit():
    """The ALLOWED audit entry must record the actual target image,
    not fall back to 'unknown' (regression: image was popped from spec
    before audit_log was called)."""
    proxy = DockerProxy()
    mock_client = MagicMock()
    proxy._client = mock_client
    mock_client.images.get.return_value = MagicMock()
    mock_container = MagicMock()
    mock_container.id = "audit-test-cid"
    mock_client.containers.run.return_value = mock_container

    spec = {
        "image": "projectdiscovery/subfinder:latest",
        "command": ["-d", "example.com"],
    }

    with patch("app.proxy.audit_log") as mock_audit:
        with patch("asyncio.to_thread", side_effect=_run_in_thread):
            await proxy.create_container(spec.copy())

    mock_audit.assert_called_once()
    call = mock_audit.call_args
    assert call.args[1] == "projectdiscovery/subfinder:latest"
    assert call.args[2] is True


@pytest.mark.asyncio
async def test_rejected_create_records_image_and_clean_reason():
    """The REJECTED audit entry must record the offending image and a
    clean reason (detail only, not the '403: ' status-code prefix)."""
    proxy = DockerProxy()
    proxy._client = MagicMock()

    spec = {"image": "malicious/image:latest"}

    with patch("app.proxy.audit_log") as mock_audit:
        with pytest.raises(HTTPException):
            with patch("asyncio.to_thread", side_effect=_run_in_thread):
                await proxy.create_container(spec.copy())

    mock_audit.assert_called_once()
    call = mock_audit.call_args
    assert call.args[1] == "malicious/image:latest"
    assert call.args[2] is False
    reason = call.args[3]
    assert "not in the whitelist" in reason
    assert not reason.startswith("403")
