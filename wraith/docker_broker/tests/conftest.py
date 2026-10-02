import pytest

from app.proxy import docker_proxy
from app.config import settings


@pytest.fixture(autouse=True)
def _configured_broker_tokens(monkeypatch):
    """Give the broker tokens deterministic values for the whole test session.

    Removing the shipped token defaults means that on a host with no ``.env``
    both tokens are empty, and the auth module correctly refuses every request.
    Tests that authenticate by forwarding ``settings.RECON_BROKER_TOKEN`` used to
    pass silently against the dev default; with no default they 401 and then
    assert against the wrong status, which is a confusing failure three files
    away from the cause.
    """
    monkeypatch.setattr(settings, "RECON_BROKER_TOKEN", "recon-broker-token-test")
    monkeypatch.setattr(
        settings, "EXPLOIT_RUNNER_BROKER_TOKEN", "runner-broker-token-test"
    )


@pytest.fixture(autouse=True)
def _reset_proxy_client():
    """Drop the cached Docker client between tests.

    ``docker_proxy`` is a module-level singleton that memoises its
    ``DockerClient`` on first use. Without this, whichever test patched
    ``app.proxy.docker.DockerClient`` first owns the mock for the rest of the
    session, and a later test asserting on ``containers.run.call_args`` reads
    the earlier test's calls -- which is how the allowlist assertion in
    test_proxy_allowed passed in isolation and failed in the full run.
    """
    docker_proxy._client = None
    yield
    docker_proxy._client = None