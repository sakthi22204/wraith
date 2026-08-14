import socket
import ipaddress
from abc import ABC, abstractmethod
from typing import List, Optional
from ..schemas import ToolResults, HostResult, PortResult, EndpointResult
from ..docker_spawner import docker_spawner


def target_url(target: str) -> str:
    """Convert a normalized host or host:port target into an HTTP URL."""
    return target if "://" in target else f"http://{target}"


def host_from_domain(domain: str) -> str:
    """Extract the bare hostname from a domain string (strip scheme, path, port)."""
    host = domain.split("://")[-1].split("/")[0]
    return host.split(":")[0] if ":" in host else host


def resolve_extra_hosts(domain: str) -> Optional[dict]:
    """Best-effort hostname -> IP mapping so Go-based tools can resolve
    Docker-internal single-label names (e.g. naabu scanning 'juice_shop').
    Non-fatal: if resolution fails the tool container falls back to its own DNS."""
    host = host_from_domain(domain)
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    try:
        return {host: socket.gethostbyname(host)}
    except OSError:
        return None


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
        raw_output = await docker_spawner.spawn_container(self.image, cmd, extra_hosts=resolve_extra_hosts(domain))
        return self.parse_output(raw_output)
