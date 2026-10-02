import logging

import httpx

from ..config import settings

logger = logging.getLogger(__name__)


class AssessmentClient:
    """Reads the coverage block the assessment service computes.

    Coverage is the evidence behind a score, and the assessment service owns
    that calculation because it owns the risk arithmetic. This client is
    deliberately forgiving: a report must still render when the assessment
    service is unavailable, because a missing coverage section is a smaller
    problem than a missing report. Failures return ``None`` and are logged,
    never raised into the request path.
    """

    def __init__(self, base_url: str = settings.ASSESSMENT_URL):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {settings.ADMIN_API_TOKEN}"}

    async def get_coverage(self, investigation_id: str):
        try:
            async with httpx.AsyncClient(headers=self.headers, timeout=30) as client:
                response = await client.get(
                    f"{self.base_url}/api/v1/assessments/{investigation_id}"
                )
                response.raise_for_status()
                payload = response.json()
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "coverage unavailable for %s: %s", investigation_id, e
            )
            return None
        coverage = payload.get("coverage")
        return coverage if isinstance(coverage, dict) else None


assessment_client = AssessmentClient()
