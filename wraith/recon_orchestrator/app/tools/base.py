from abc import ABC, abstractmethod
from typing import List
from ..schemas import ToolResults, HostResult, PortResult, EndpointResult
from ..docker_spawner import docker_spawner

class ReconTool(ABC):
    def __init__(self, name: str, image: str):
        self.name = name
        self.image = image

    @abstractmethod
    def get_command(self, domain: str) -> List[str]:
        pass

    @abstractmethod
    def parse_output(self, output: str) -> ToolResults:
        pass

    async def run(self, domain: str) -> ToolResults:
        cmd = self.get_command(domain)
        raw_output = await docker_spawner.spawn_container(self.image, cmd)
        return self.parse_output(raw_output)
