import httpx
from .config import settings
from .schemas import HostResult, PortResult, EndpointResult

class GraphClient:
    def __init__(self, base_url: str = settings.GRAPH_DB_URL):
        self.base_url = base_url
        headers = {"Authorization": f"Bearer {settings.ADMIN_API_TOKEN}"}
        self._client = httpx.AsyncClient(base_url=base_url, headers=headers)

    async def close(self):
        await self._client.aclose()

    async def create_scan_session(self, program_id: str):
        response = await self._client.post(
            "/scan-sessions",
            params={"program_id": program_id}
        )
        response.raise_for_status()
        return response.json()

    async def get_program_scope(self, program_id: str):
        response = await self._client.get(f"/programs/{program_id}")
        response.raise_for_status()
        data = response.json()
        return data.get("scope_domains", [])

    async def update_scan_session(self, session_id: str, status: str):
        response = await self._client.patch(
            f"/scan-sessions/{session_id}",
            params={"status": status}
        )
        response.raise_for_status()
        return response.json()

    async def upsert_host(self, program_id: str, host: HostResult):
        response = await self._client.post(
            f"/programs/{program_id}/hosts",
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
                "state": port.state
            }
        )
        response.raise_for_status()
        return response.json()

    async def upsert_endpoint(self, host_id: str, endpoint: EndpointResult):
        response = await self._client.post(
            f"/hosts/{host_id}/endpoints",
            json={
                "url": endpoint.url,
                "method": endpoint.method
            }
        )
        response.raise_for_status()
        return response.json()

    async def create_finding(self, target_id: str, target_type: str, finding_data: dict):
        # Note: graph_db API contract for /findings takes FindingCreate model
        # which now includes target_id and target_type in the body based on Phase 1 updates.
        payload = {**finding_data, "target_id": target_id, "target_type": target_type}
        response = await self._client.post(
            "/findings",
            json=payload
        )
        response.raise_for_status()
        return response.json()

graph_client = GraphClient()
