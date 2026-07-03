import docker
import asyncio
from typing import List
from .config import settings

class DockerSpawner:
    def __init__(self, docker_url: str = settings.DOCKER_SOCKET):
        self.client = docker.DockerClient(base_url=docker_url)

    async def spawn_container(self, image: str, cmd: List[str], timeout: int = settings.TOOL_TIMEOUT) -> str:
        def run():
            container = None
            try:
                container = self.client.containers.run(
                    image=image,
                    command=cmd,
                    mem_limit=settings.MEM_LIMIT,
                    cpu_quota=settings.CPU_QUOTA,
                    detach=True,
                    remove=False # We want to capture logs before removing
                )

                try:
                    result = container.wait(timeout=timeout)
                    logs = container.logs().decode("utf-8")
                    if result["StatusCode"] != 0:
                        # You might want to handle non-zero exit codes differently
                        pass
                    return logs
                except Exception as e:
                    # Timeout or other error during wait
                    raise e
            finally:
                if container:
                    try:
                        container.stop(timeout=1)
                    except:
                        pass
                    try:
                        container.remove(force=True)
                    except:
                        pass

        # Run the blocking docker call in a thread pool to keep it async
        return await asyncio.to_thread(run)

docker_spawner = DockerSpawner()
