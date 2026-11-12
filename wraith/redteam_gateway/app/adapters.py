"""Thin BeEF and Empire API clients.

Both are intentionally small: the gateway owns authorization and the module
allowlist, while these classes only perform the tasking call. Every request is
bounded by a timeout so a wedged C2 server cannot hold the agent open.
"""

import os
import re
from typing import Any, Dict, Optional

import httpx

REQUEST_TIMEOUT_SECONDS = float(os.getenv("C2_REQUEST_TIMEOUT_SECONDS", "60"))


class C2Error(RuntimeError):
    """The C2 server refused, was unreachable, or returned an unusable reply."""


def _compact(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _module_matches(module: str, item: Dict[str, Any]) -> bool:
    """Match an allowlist key to BeEF's module record.

    BeEF identifies a module by a numeric database id, while operators think in
    keys like ``browser_details``. The listing exposes the Ruby class and the
    human name; compare compact forms so ``BrowserDetails`` and "Browser
    Details" both match without a giant hand-maintained alias table.
    """
    wanted = _compact(module)
    if not wanted:
        return False
    candidates = [item.get("class", ""), item.get("name", "")]
    for candidate in candidates:
        text = str(candidate or "")
        if "::" in text:
            text = text.rsplit("::", 1)[-1]
        if _compact(text) == wanted:
            return True
    return False


class BeefClient:
    def __init__(self, base_url: str | None = None, token: str | None = None,
                 username: str | None = None, password: str | None = None):
        self.base_url = (base_url or os.getenv("BEEF_API_URL", "http://beef:3000")).rstrip("/")
        self.token = token if token is not None else os.getenv("BEEF_API_TOKEN", "")
        self.username = username if username is not None else os.getenv("BEEF_USERNAME", "")
        self.password = password if password is not None else os.getenv("BEEF_PASSWORD", "")

    def _params(self, token: str) -> dict:
        return {"token": token}

    async def _auth_token(self, client: httpx.AsyncClient) -> str:
        """BeEF rotates its REST token at startup, so a static env token goes
        stale. Log in with the configured admin credentials unless a caller
        deliberately supplied a current token."""
        if self.token:
            return self.token
        if not self.username or not self.password:
            raise C2Error(
                "BeEF credentials are not configured; set BEEF_USERNAME/BEEF_PASSWORD "
                "or a current BEEF_API_TOKEN"
            )
        response = await client.post(
            f"{self.base_url}/api/admin/login",
            json={"username": self.username, "password": self.password},
        )
        if response.status_code >= 400:
            raise C2Error(f"BeEF login failed with HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError as exc:
            raise C2Error("BeEF login returned a non-JSON response") from exc
        token = data.get("token") if isinstance(data, dict) else None
        if not token:
            raise C2Error("BeEF login response did not contain a token")
        return str(token)

    async def _resolve_module_id(self, client: httpx.AsyncClient, token: str,
                                 module: str) -> str:
        response = await client.get(
            f"{self.base_url}/api/modules", params=self._params(token),
        )
        if response.status_code >= 400:
            raise C2Error(
                f"BeEF module listing returned HTTP {response.status_code}: {response.text[:500]}"
            )
        try:
            modules = response.json()
        except ValueError as exc:
            raise C2Error("BeEF returned a non-JSON module listing") from exc
        # Current BeEF releases key the listing by index as a JSON object
        # ({"0": {...}, "1": {...}}); older ones returned a bare array. Accept
        # both, but still refuse anything that is not module records.
        if isinstance(modules, dict):
            modules = list(modules.values())
        if not isinstance(modules, list):
            raise C2Error("BeEF module listing was neither an array nor an object")
        for item in modules:
            if isinstance(item, dict) and _module_matches(module, item):
                module_id = item.get("id")
                if module_id is not None:
                    return str(module_id)
        raise C2Error(f"BeEF module {module!r} was not found in the module listing")

    async def execute(self, session_id: str, module: str, options: Dict[str, Any]) -> Dict[str, Any]:
        if not session_id:
            raise C2Error("beef_command requires an existing BeEF session id")
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            token = await self._auth_token(client)
            module_id = await self._resolve_module_id(client, token, module)
            response = await client.post(
                f"{self.base_url}/api/modules/{session_id}/{module_id}",
                params=self._params(token), json=options or {},
            )
            if response.status_code >= 400:
                raise C2Error(
                    f"BeEF returned HTTP {response.status_code}: {response.text[:500]}"
                )
            try:
                data = response.json()
            except ValueError as exc:
                raise C2Error("BeEF returned a non-JSON response") from exc
            return data if isinstance(data, dict) else {"response": data}


class EmpireClient:
    """Empire v2 tasking client.

    Auth is a conventional OAuth2 password flow at the server root
    (``POST /token`` with form fields), and modules are tasked on the agent:
    ``POST /api/v2/agents/{agent}/tasks/module`` with ``module_id`` and
    ``options`` in the JSON body. The module id is the slash-delimited module
    path, not a numeric id.
    """

    def __init__(self, base_url: str | None = None, token: str | None = None):
        root = (base_url or os.getenv("EMPIRE_API_URL", "http://empire:1337")).rstrip("/")
        suffix = "/api/v2"
        if root.endswith(suffix):
            root = root[: -len(suffix)]
        self.base_url = root
        self.api_url = f"{root}{suffix}"
        self.token = token if token is not None else os.getenv("EMPIRE_API_TOKEN", "")
        self.username = os.getenv("EMPIRE_USERNAME", "")
        self.password = os.getenv("EMPIRE_PASSWORD", "")

    async def _auth_token(self, client: httpx.AsyncClient) -> str:
        if self.token:
            return self.token
        if not self.username or not self.password:
            raise C2Error(
                "Empire credentials are not configured; set EMPIRE_API_TOKEN or "
                "EMPIRE_USERNAME/EMPIRE_PASSWORD"
            )
        response = await client.post(
            f"{self.base_url}/token",
            data={"username": self.username, "password": self.password},
        )
        if response.status_code >= 400:
            raise C2Error(f"Empire login failed with HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError as exc:
            raise C2Error("Empire login returned a non-JSON response") from exc
        token = data.get("access_token") if isinstance(data, dict) else None
        if not token:
            raise C2Error("Empire login response did not contain an access token")
        return str(token)

    async def execute(self, agent: str, module: str, options: Dict[str, Any]) -> Dict[str, Any]:
        if not agent:
            raise C2Error("empire_task requires an existing Empire agent id")
        if not module:
            raise C2Error("empire_task requires a module id")
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            token = await self._auth_token(client)
            headers = {"Authorization": f"Bearer {token}"}
            response = await client.post(
                f"{self.api_url}/agents/{agent}/tasks/module",
                headers=headers,
                json={"module_id": module, "options": options or {}},
            )
            if response.status_code >= 400:
                raise C2Error(
                    f"Empire returned HTTP {response.status_code}: {response.text[:500]}"
                )
            try:
                data = response.json()
            except ValueError as exc:
                raise C2Error("Empire returned a non-JSON response") from exc
            return data if isinstance(data, dict) else {"response": data}
