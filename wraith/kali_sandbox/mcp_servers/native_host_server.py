from typing import Any, Dict, Optional

import httpx

from .common.base_server import BaseSecurityServer
from .common.redaction import redact_text, redact_url
from .config import settings

MAX_EVIDENCE_CHARS = 65536


def _redact_value(value: Any, depth: int = 0) -> Any:
    if depth > 8:
        return ""
    if isinstance(value, dict):
        return {str(k): _redact_value(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(v, depth + 1) for v in value[:100]]
    if isinstance(value, str):
        return redact_text(value[:MAX_EVIDENCE_CHARS])
    return value


class NativeHostServer(BaseSecurityServer):
    def __init__(self):
        super().__init__("Native Host Server")
        self.setup_tools()

    def setup_tools(self):
        @self.mcp.tool()
        async def native_host_probe(
            target_url: str = "", native_host_job: Optional[dict] = None
        ):
            return await self.native_host_probe(
                target_url=target_url, native_host_job=native_host_job
            )

    async def native_host_probe(self, target_url: str = "", native_host_job: Optional[dict] = None):
        job: Dict[str, Any] = native_host_job if isinstance(native_host_job, dict) else {}
        destination = str(target_url or job.get("target_url") or "")
        bridge = str(getattr(settings, "NATIVE_HOST_BRIDGE_URL", "") or "")
        token = str(getattr(settings, "NATIVE_HOST_BRIDGE_TOKEN", "") or "")
        result = {
            "evidence": {},
            "cleanup": {},
            "target_url": redact_url(destination) if destination else "",
            "status": "error",
        }
        if not bridge:
            result["error"] = "native host bridge URL is not configured"
            return result
        if not token:
            result["error"] = "native host bridge token is not configured"
            return result
        if not destination:
            result["error"] = "native host probe has no target_url"
            return result
        try:
            configured = float(getattr(settings, "NATIVE_HOST_PROBE_TIMEOUT", 5.0) or 5.0)
        except (TypeError, ValueError):
            configured = 5.0
        timeout = max(0.1, min(configured, 15.0))
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    bridge.rstrip("/") + "/jobs",
                    headers={
                        "X-Wraith-Bridge-Token": token,
                        "Content-Type": "application/json",
                    },
                    json=job,
                )
        except Exception as exc:
            result["error"] = f"{type(exc).__name__}: {str(exc)[:512]}"
            return result
        if response.status_code != 200:
            result["error"] = f"native host bridge returned {response.status_code}"
            return result
        try:
            data = response.json()
        except Exception as exc:
            result["error"] = f"native host bridge response was not JSON: {type(exc).__name__}"
            return result
        if not isinstance(data, dict):
            result["error"] = "native host bridge response was not an object"
            return result
        evidence = data.get("evidence")
        cleanup = data.get("cleanup")
        result["evidence"] = _redact_value(evidence if isinstance(evidence, dict) else {})
        result["cleanup"] = _redact_value(cleanup if isinstance(cleanup, dict) else {})
        if data.get("target_url"):
            result["target_url"] = redact_url(str(data["target_url"]))
        result["status"] = "ok"
        return result
