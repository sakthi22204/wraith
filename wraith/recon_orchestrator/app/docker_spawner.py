import httpx
import asyncio
import logging
from typing import List, Optional
from .config import settings

logger = logging.getLogger(__name__)


class ToolAborted(Exception):
    """A tool container did not exit on its own terms.

    Carries whatever the container had flushed to stdout/stderr so a caller can
    still parse the partial output: a scan stopped at its deadline has findings
    worth keeping, and discarding them would report "0 findings" for work that
    actually ran.
    """

    def __init__(self, message: str, logs: str = ""):
        super().__init__(message)
        self.logs = logs or ""


class ToolDeadlineReached(ToolAborted):
    """The pass exceeded its wall-clock budget; the broker stopped the container."""


class ToolOOMKilled(ToolAborted):
    """The container was killed by the runtime for exceeding its memory limit.

    Not retried: the same command against the same limit OOMs again, and each
    attempt spends minutes of the session's budget to learn that again.
    """


class DockerSpawner:
    def __init__(self, broker_url: str = settings.DOCKER_BROKER_URL):
        self.broker_url = broker_url

    async def spawn_container(self, image: str, cmd: List[str], timeout: int = settings.TOOL_TIMEOUT, volumes: Optional[dict] = None, extra_hosts: Optional[dict] = None, environment: Optional[dict] = None, mem_limit: Optional[str] = None, cpu_quota: Optional[int] = None) -> str:
        headers = {"Authorization": f"Bearer {settings.RECON_BROKER_TOKEN}"}
        async with httpx.AsyncClient(timeout=timeout + 30, headers=headers) as client:
            spec = {
                "image": image,
                "command": cmd,
                "mem_limit": mem_limit or settings.MEM_LIMIT,
                "cpu_quota": cpu_quota or settings.CPU_QUOTA,
                "network": settings.RECON_DOCKER_NETWORK,
                "detach": True,
                "remove": False
                # "caller" removed as it is now derived from the bearer token
            }
            if volumes:
                spec["volumes"] = volumes
            if extra_hosts:
                spec["extra_hosts"] = extra_hosts
            if environment:
                spec["environment"] = environment

            # 1. Create and run
            create_res = await client.post(f"{self.broker_url}/containers", json=spec)
            create_res.raise_for_status()
            container_id = create_res.json()["container_id"]

            try:
                # 2. Wait
                wait_res = await client.post(
                    f"{self.broker_url}/containers/{container_id}/wait",
                    params={"timeout": timeout}
                )
                wait_res.raise_for_status()
                wait_payload = wait_res.json()

                # 3. Get logs
                log_res = await client.get(
                    f"{self.broker_url}/containers/{container_id}/logs"
                )
                log_res.raise_for_status()
                logs = log_res.json()["logs"]
            finally:
                # 4. Cleanup (retry transient failures so a timed-out tool never leaves an orphan container)
                last_error = None
                for attempt in range(1, 4):
                    try:
                        await client.delete(
                            f"{self.broker_url}/containers/{container_id}"
                        )
                        last_error = None
                        break
                    except httpx.HTTPError as e:
                        last_error = e
                        logger.warning(f"Failed to cleanup container '{container_id}' on broker (attempt {attempt}/3): {e}")
                        await asyncio.sleep(1)
                if last_error:
                    logger.warning(f"Container '{container_id}' was NOT cleaned up after 3 attempts.")

            # Raised after cleanup (the finally above has already run) so an
            # aborted scan never leaves its container behind, and with the
            # container's logs attached so the caller keeps the partial output.
            if wait_payload.get("OOMKilled"):
                raise ToolOOMKilled(
                    f"Tool container exceeded its memory limit after {timeout}s", logs
                )
            if wait_payload.get("TimedOut") or wait_payload.get("StatusCode") == -1:
                raise ToolDeadlineReached(
                    f"Tool container exceeded its {timeout}s budget and was stopped", logs
                )
            return logs

docker_spawner = DockerSpawner()
