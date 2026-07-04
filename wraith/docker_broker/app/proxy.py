import docker
import asyncio
from typing import List, Optional
from .config import settings
from .validators import validate_container_spec
from .audit import audit_log

class DockerProxy:
    def __init__(self):
        self.client = docker.DockerClient(base_url=settings.DOCKER_SOCKET)

    async def create_container(self, spec: dict):
        # Spec can contain: image, command, mem_limit, cpu_quota, detach, remove, etc.
        try:
            validate_container_spec(spec)

            def run():
                # Extract image and command to call correctly
                image = spec.pop("image")
                command = spec.pop("command", None)
                container = self.client.containers.run(
                    image=image,
                    command=command,
                    **spec
                )
                return container.id

            container_id = await asyncio.to_thread(run)
            audit_log("CREATE", spec.get("image", "unknown"), True)
            return container_id
        except Exception as e:
            audit_log("CREATE", spec.get("image", "unknown"), False, str(e))
            raise e

    async def wait_container(self, container_id: str, timeout: Optional[int] = None):
        def run():
            container = self.client.containers.get(container_id)
            return container.wait(timeout=timeout)
        return await asyncio.to_thread(run)

    async def get_logs(self, container_id: str):
        def run():
            container = self.client.containers.get(container_id)
            return container.logs().decode("utf-8")
        return await asyncio.to_thread(run)

    async def stop_container(self, container_id: str):
        def run():
            container = self.client.containers.get(container_id)
            container.stop()
        await asyncio.to_thread(run)

    async def remove_container(self, container_id: str):
        def run():
            container = self.client.containers.get(container_id)
            container.remove(force=True)
        await asyncio.to_thread(run)

docker_proxy = DockerProxy()
