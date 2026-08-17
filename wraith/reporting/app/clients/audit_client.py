import httpx
from ..config import settings

class AuditClient:
    def __init__(self, base_url: str = settings.ACTIVE_EXPLOIT_RUNNER_URL):
        self.base_url = base_url

    async def get_audit_entries(self, investigation_id: str, target: str = None):
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(f"{self.base_url}/audit/{investigation_id}")
                response.raise_for_status()
                entries = response.json()
                if target:
                    return [e for e in entries if e["target"] == target]
                return entries
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.HTTPStatusError):
            return []

audit_client = AuditClient()