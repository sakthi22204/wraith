"""Grant verification shared by the gateway and the runner's mint.

The gateway does not decide whether a C2 action is in scope. It asks the runner
for a short-lived HMAC grant, then verifies that the grant it received is bound
to this gateway, this investigation, this target host, and this action. A
gateway that is tricked into forwarding a different target or action therefore
fails its own check rather than trusting its own request body.
"""

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Dict
from urllib.parse import urlparse

GRANT_VERSION = 1
DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_grant(token: str, secret: str, *, now: float | None = None) -> Dict[str, Any]:
    if not secret:
        raise ValueError("gate secret is not configured; refusing to trust any grant")
    if not token or not isinstance(token, str) or token.count(".") != 1:
        raise ValueError("malformed grant")
    body_b64, sig_b64 = token.split(".")
    try:
        body = _b64d(body_b64)
        signature = _b64d(sig_b64)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("malformed grant encoding") from exc

    expected = hmac.new(secret.encode(), body, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("grant signature is not valid for this gate secret")

    try:
        payload = json.loads(body)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("grant payload is not readable") from exc
    if not isinstance(payload, dict) or payload.get("v") != GRANT_VERSION:
        raise ValueError("unsupported grant version")
    if int(payload.get("exp", 0)) < int(now if now is not None else time.time()):
        raise ValueError("grant has expired")
    return payload


def authority_of(url: str) -> str:
    candidate = (url or "").strip()
    if "://" not in candidate:
        candidate = "http://" + candidate
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return ""
    if not host:
        return ""
    if port is None:
        port = DEFAULT_PORTS.get((parsed.scheme or "").lower())
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{port}" if port else host
