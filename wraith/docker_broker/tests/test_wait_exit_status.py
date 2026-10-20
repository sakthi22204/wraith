"""The /wait response must say WHY a container stopped, not only with what.

StatusCode alone cannot separate the outcomes a caller acts on differently:
an OOM kill and a tool's own non-zero exit both arrive as numbers, and a
deadline stop (-1) is indistinguishable from a tool that exited -1 itself.
The recon spawner keys "do not retry, keep the partial output" off these
flags, so their presence in every return shape is the contract.
"""
import pytest

from app.proxy import DockerProxy


def _running_proxy(status="running", exit_code=0, oom=False):
    proxy = DockerProxy()
    container = type("C", (), {})()
    container.attrs = {
        "State": {"Status": status, "ExitCode": exit_code, "OOMKilled": oom},
    }
    container.stop = lambda timeout=5: None
    client = type("Client", (), {})()
    client.containers = type("Containers", (), {})()
    client.containers.get = lambda cid: container
    proxy._client = client
    return proxy


@pytest.mark.asyncio
async def test_a_clean_exit_reports_both_flags_false():
    proxy = _running_proxy(status="exited", exit_code=0)
    result = await proxy.wait_container("c1", timeout=5)
    assert result["StatusCode"] == 0
    assert result["TimedOut"] is False
    assert result["OOMKilled"] is False


@pytest.mark.asyncio
async def test_an_oom_kill_is_flagged_for_the_caller():
    proxy = _running_proxy(status="exited", exit_code=137, oom=True)
    result = await proxy.wait_container("c1", timeout=5)
    assert result["OOMKilled"] is True
    assert result["TimedOut"] is False
    assert result["StatusCode"] == 137


@pytest.mark.asyncio
async def test_a_deadline_stop_is_flagged_as_timed_out():
    # A negative budget: the first poll is already past it, so the stop path
    # runs deterministically instead of sleeping a poll interval in a test.
    proxy = _running_proxy(status="running")
    result = await proxy.wait_container("c1", timeout=-1)
    assert result["TimedOut"] is True
    assert result["OOMKilled"] is False
    assert result["StatusCode"] == -1


@pytest.mark.asyncio
async def test_a_container_already_removed_is_not_an_abort():
    import docker

    proxy = DockerProxy()

    def gone(cid):
        raise docker.errors.NotFound("gone")

    client = type("Client", (), {})()
    client.containers = type("Containers", (), {})()
    client.containers.get = gone
    proxy._client = client

    result = await proxy.wait_container("c1", timeout=5)
    assert result["TimedOut"] is False
    assert result["OOMKilled"] is False
