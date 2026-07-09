import httpx
import asyncio
from typing import List
from .config import settings

class DockerSpawner:
    def __init__(self, broker_url: str = settings.DOCKER_BROKER_URL):
        self.broker_url = broker_url

    async def spawn_container(self, image: str, cmd: List[str], timeout: int = settings.TOOL_TIMEOUT) -> str:
        headers = {"Authorization": f"Bearer {settings.DOCKER_BROKER_TOKEN}"}
        async with httpx.AsyncClient(timeout=timeout + 30, headers=headers) as client:
            spec = {
                "image": image,
                "command": cmd,
                "mem_limit": settings.MEM_LIMIT,
                "cpu_quota": settings.CPU_QUOTA,
                "detach": True,
                "remove": False,
                "caller": "recon_orchestrator"
            }

            # 1. Create and run
            create_res = await client.post(f"{self.broker_url}/containers", json=spec)
            create_res.raise_for_status()
            container_id = create_res.json()["container_id"]

            try:
                # 2. Wait
                wait_res = await client.post(
                    f"{self.broker_url}/containers/{container_id}/wait",
                    params={"timeout": timeout, "caller": "recon_orchestrator"}
                )
                wait_res.raise_for_status()

                # 3. Get logs
                log_res = await client.get(
                    f"{self.broker_url}/containers/{container_id}/logs",
                    params={"caller": "recon_orchestrator"}
                )
                log_res.raise_for_status()
                return log_res.json()["logs"]
            finally:
                # 4. Cleanup
                try:
                    await client.delete(
                        f"{self.broker_url}/containers/{container_id}",
                        params={"caller": "recon_orchestrator"}
                    )
                except:
                    pass

docker_spawner = DockerSpawner()
