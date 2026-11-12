"""OWASP ZAP adapter exposed as gated MCP tools.

ZAP runs as a separate container, so this server speaks its JSON API rather
than spawning a process. Both tools still obey the same contract as the rest of
the stack: the runner has already checked the killswitch, scope, aggressiveness
and rate limit, and the sandbox gate independently re-checks the signed grant
and scope before this module is reached.

The two modes are deliberately different:

* ``run_zap_baseline`` is a spider plus ZAP's passive scanner. It sends only
  ordinary requests, so it does not require an aggressive authorization.
* ``run_zap_active`` runs ZAP's active scanner, which sends attack payloads and
  therefore only ever arrives through the runner's aggressive-action path.

Findings are returned as text observations and persisted by the runner's
existing graph sync. They remain UNCONFIRMED evidence in the graph; ZAP's
severity is a lead, not a validation verdict.
"""

import asyncio
import json
import os
from typing import Dict, List, Optional
from urllib.parse import urlencode

import httpx

from .common.base_server import BaseSecurityServer
from .common.parsers import ZapResult

ZAP_API_URL = os.getenv("ZAP_API_URL", "http://zap:8080").rstrip("/")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")
ZAP_TIMEOUT_SECONDS = int(os.getenv("ZAP_TIMEOUT_SECONDS", "600"))
ZAP_POLL_SECONDS = 1.0


class ZapError(RuntimeError):
    """ZAP could not be reached or refused the request."""


class ZapServer(BaseSecurityServer):
    def __init__(self):
        super().__init__("ZAP Server")
        # Every provider registers its inner MCP tools in __init__; without this
        # the outer run_zap_* wrapper reaches an empty inner server and fails
        # with "Unknown tool", which the runner only sees as an opaque 500.
        self.setup_tools()

    def _api_key(self) -> str:
        if not ZAP_API_KEY:
            raise ZapError("ZAP_API_KEY is not configured; refusing to contact ZAP")
        return ZAP_API_KEY

    def _url(self, component: str, view: str, **params) -> str:
        query = {"apikey": self._api_key()}
        query.update({k: v for k, v in params.items() if v is not None})
        return f"{ZAP_API_URL}/JSON/{component}/{view}/?{urlencode(query)}"

    async def _get(self, client: httpx.AsyncClient, component: str, view: str, **params):
        response = await client.get(self._url(component, view, **params))
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise ZapError(f"ZAP returned a non-object response for {component}/{view}")
        return data

    async def _action(self, client: httpx.AsyncClient, component: str, action: str,
                      **params):
        # ZAP's REST actions accept GET, and its POST handler rejects the
        # content type httpx sends for an empty body. Actions have no request
        # body here, so GET is the reliable form.
        response = await client.get(self._url(component, action, **params))
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise ZapError(f"ZAP returned a non-object response for {component}/{action}")
        return data

    @staticmethod
    def _scan_id(data: dict) -> Optional[str]:
        value = data.get("scan")
        return str(value) if value is not None else None

    async def _wait_for_status(self, client: httpx.AsyncClient, component: str,
                               scan_id: str) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + ZAP_TIMEOUT_SECONDS
        while loop.time() < deadline:
            data = await self._get(client, component, "view/status", scanId=scan_id)
            status = str(data.get("status", "0"))
            if status == "100":
                return
            await asyncio.sleep(ZAP_POLL_SECONDS)
        raise ZapError(f"ZAP {component} scan {scan_id} did not finish within {ZAP_TIMEOUT_SECONDS}s")

    async def _stop_scan(self, client: httpx.AsyncClient, component: str,
                         scan_id: str) -> None:
        try:
            await self._action(client, component, "action/stop", scanId=scan_id)
        except Exception:
            pass

    async def _wait_for_passive(self, client: httpx.AsyncClient) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + ZAP_TIMEOUT_SECONDS
        while loop.time() < deadline:
            data = await self._get(client, "pscan", "view/recordsToScan")
            remaining = str(data.get("recordsToScan", "0"))
            if remaining == "0":
                return
            await asyncio.sleep(ZAP_POLL_SECONDS)
        raise ZapError(f"ZAP passive scanner did not finish within {ZAP_TIMEOUT_SECONDS}s")

    async def _alerts(self, client: httpx.AsyncClient, url: str) -> List[dict]:
        data = await self._get(client, "core", "view/alerts", baseurl=url)
        alerts = data.get("alerts", [])
        return alerts if isinstance(alerts, list) else []

    @staticmethod
    def _finding_lines(alerts: List[dict]) -> List[str]:
        findings: List[str] = []
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            name = str(alert.get("alert") or alert.get("name") or "ZAP alert").strip()
            risk = str(alert.get("risk") or alert.get("riskdesc") or "Informational").strip()
            url = str(alert.get("url") or "").strip()
            parameter = str(alert.get("param") or "").strip()
            suffix = f" at {url}" if url else ""
            if parameter:
                suffix += f" (parameter: {parameter})"
            findings.append(f"[{risk}] {name}{suffix}")
        return findings

    async def _scan(self, url: str, active: bool) -> ZapResult:
        self.validate_url(url)
        tool = "zap_active" if active else "zap_baseline"
        if not ZAP_API_KEY:
            return ZapResult(
                tool=tool, target=url, findings=[], inconclusive=True,
                raw_output="ZAP_API_KEY is not configured; no scan was started.",
            )

        scan_id = None
        component = "ascan" if active else "spider"
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                version = (await self._get(client, "core", "view/version")).get("version")
                spider_id = self._scan_id(await self._action(
                    client, "spider", "action/scan", url=url, recurse="true"))
                if not spider_id:
                    raise ZapError("ZAP did not return a spider scan id")
                await self._wait_for_status(client, "spider", spider_id)

                if active:
                    scan_id = self._scan_id(await self._action(
                        client, "ascan", "action/scan", url=url,
                        recurse="true", inScopeOnly="false"))
                    if not scan_id:
                        raise ZapError("ZAP did not return an active scan id")
                    await self._wait_for_status(client, "ascan", scan_id)
                else:
                    await self._wait_for_passive(client)

                alerts = await self._alerts(client, url)
                raw = json.dumps({"zap_version": version, "active": active, "alerts": alerts},
                                 indent=2)
                return ZapResult(
                    tool=tool, target=url, findings=self._finding_lines(alerts),
                    inconclusive=False, raw_output=raw,
                )
        except Exception as exc:
            if scan_id:
                try:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        await self._stop_scan(client, component, scan_id)
                except Exception:
                    pass
            return ZapResult(
                tool=tool, target=url, findings=[], inconclusive=True,
                raw_output=f"{type(exc).__name__}: {exc}",
            )

    def setup_tools(self):
        @self.mcp.tool()
        async def run_zap_baseline(url: str, caller: Optional[str] = None) -> ZapResult:
            """Spider a URL and collect ZAP's passive findings.

            Sends only ordinary requests and does not use attack payloads.
            Gated on scope and a signed grant; findings remain unconfirmed
            evidence until independently validated.
            """
            self.verify_caller("run_zap_baseline", caller)
            return await self._scan(url, active=False)

        @self.mcp.tool()
        async def run_zap_active(url: str, caller: Optional[str] = None) -> ZapResult:
            """Run ZAP's active scanner against a URL.

            Sends attack payloads, so the runner only dispatches this action
            when the covering scope rule carries ``allow_aggressive``. Gated on
            scope and a signed grant; findings remain unconfirmed evidence until
            independently validated.
            """
            self.verify_caller("run_zap_active", caller)
            return await self._scan(url, active=True)
