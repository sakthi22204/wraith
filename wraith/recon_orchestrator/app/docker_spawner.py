import httpx
import asyncio
import logging
from typing import List, Optional
from .config import settings

logger = logging.getLogger(__name__)

class DockerSpawner:
    def __init__(self, broker_url: str = settings.DOCKER_BROKER_URL):
        self.broker_url = broker_url

    async def spawn_container(self, image: str, cmd: List[str], timeout: int = settings.TOOL_TIMEOUT, volumes: Optional[dict] = None, extra_hosts: Optional[dict] = None) -> str:
        headers = {"Authorization": f"Bearer {settings.RECON_BROKER_TOKEN}"}
        async with httpx.AsyncClient(timeout=timeout + 30, headers=headers) as client:
            spec = {
                "image": image,
                "command": cmd,
                "mem_limit": settings.MEM_LIMIT,
                "cpu_quota": settings.CPU_QUOTA,
                "network": settings.RECON_DOCKER_NETWORK,
                "detach": True,
                "remove": False
                # "caller" removed as it is now derived from the bearer token
            }
            if volumes:
                spec["volumes"] = volumes
            if extra_hosts:
                spec["extra_hosts"] = extra_hosts

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

                # 3. Get logs
                log_res = await client.get(
                    f"{self.broker_url}/containers/{container_id}/logs"
                )
                log_res.raise_for_status()
                return log_res.json()["logs"]
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

docker_spawner = DockerSpawner()
