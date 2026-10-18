import httpx
from typing import List, Optional
from .config import settings
from .schemas import HostResult, PortResult, EndpointResult

class GraphClient:
    def __init__(self, base_url: str = settings.GRAPH_DB_URL):
        self.base_url = base_url
        headers = {"Authorization": f"Bearer {settings.ADMIN_API_TOKEN}"}
        self._client = httpx.AsyncClient(base_url=base_url, headers=headers)

    async def close(self):
        await self._client.aclose()

    async def create_scan_session(self, investigation_id: str):
        response = await self._client.post(
            "/scan-sessions",
            params={"investigation_id": investigation_id}
        )
        response.raise_for_status()
        return response.json()

    async def create_recon_session(self, session_id: str, investigation_id: str, domains: List[str], status: str):
        response = await self._client.post(
            "/recon-sessions",
            params={
                "session_id": session_id,
                "investigation_id": investigation_id,
                "status": status
            },
            json=domains
        )
        response.raise_for_status()
        return response.json()

    async def update_recon_session(self, session_id: str, status: str, tool_results: Optional[dict] = None):
        response = await self._client.patch(
            f"/recon-sessions/{session_id}",
            params={"status": status},
            json=tool_results
        )
        response.raise_for_status()
        return response.json()

    async def list_recon_sessions(self, investigation_id: str):
        response = await self._client.get(
            "/recon-sessions",
            params={"investigation_id": investigation_id}
        )
        response.raise_for_status()
        return response.json()

    async def get_recon_session(self, session_id: str):
        response = await self._client.get(f"/recon-sessions/{session_id}")
        response.raise_for_status()
        return response.json()

    async def get_investigation(self, investigation_id: str):
        response = await self._client.get(f"/investigations/{investigation_id}")
        response.raise_for_status()
        return response.json()

    async def get_program_scope(self, program_id: str):
        data = await self.get_investigation(program_id)
        return data.get("scope_domains", [])

    async def get_investigation_scope(self, investigation_id: str):
        # Standard implementation delegates to get_program_scope to support legacy test patching perfectly
        return await self.get_program_scope(investigation_id)

    async def update_scan_session(self, session_id: str, status: str):
        response = await self._client.patch(
            f"/scan-sessions/{session_id}",
            params={"status": status}
        )
        response.raise_for_status()
        return response.json()

    async def upsert_host(self, investigation_id: str, host: HostResult):
        response = await self._client.post(
            f"/investigations/{investigation_id}/hosts",
            json={"value": host.value}
        )
        response.raise_for_status()
        return response.json()

    async def upsert_port(self, host_id: str, port: PortResult):
        response = await self._client.post(
            f"/hosts/{host_id}/ports",
            json={
                "number": port.number,
                "protocol": port.protocol,
                "state": port.state,
                "source_tool": port.source_tool
            }
        )
        response.raise_for_status()
        return response.json()

    async def upsert_endpoint(self, host_id: str, endpoint: EndpointResult):
        response = await self._client.post(
            f"/hosts/{host_id}/endpoints",
            json={
                "url": endpoint.url,
                "method": endpoint.method,
                "source_tool": endpoint.source_tool
            }
        )
        response.raise_for_status()
        return response.json()

    async def create_finding(self, target_id: str, target_type: str, finding_data: dict):
        payload = {**finding_data, "target_id": target_id, "target_type": target_type}
        response = await self._client.post(
            "/findings",
            json=payload
        )
        response.raise_for_status()
        return response.json()

graph_client = GraphClient()
