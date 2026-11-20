from __future__ import annotations

import os
import re
import uuid
from urllib.parse import urlsplit

BUILTIN_ACTIONS = frozenset(
    {
        "load_probe",
        "module_check",
        "log_write",
        "log_verify",
        "process_self",
        "cleanup",
    }
)
FILE_CREATING_ACTIONS = frozenset({"load_probe", "log_write"})
DEFAULT_HOST_SUFFIX = "native.invalid"
TOKEN_MIN_LENGTH = 12
TOKEN_MAX_LENGTH = 512
JOB_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
HOST_ID_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class PolicyError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def csv_env(name: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, "").split(",") if item.strip()]


def canonical_target_url(host_id: str) -> str:
    return f"https://{host_id}.{DEFAULT_HOST_SUFFIX}/.wraith/native"


def agent_map() -> dict[str, str]:
    result: dict[str, str] = {}
    for entry in csv_env("NATIVE_HOST_AGENTS"):
        if "=" not in entry:
            continue
        host_id, url = (part.strip() for part in entry.split("=", 1))
        host_id = host_id.lower()
        if not HOST_ID_RE.fullmatch(host_id):
            continue
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            continue
        if parts.username or parts.password:
            continue
        result[host_id] = url.rstrip("/")
    return result


def allowed_host_ids(agents: dict[str, str] | None = None) -> set[str]:
    configured = {item.lower() for item in csv_env("NATIVE_HOST_ALLOWED_HOST_IDS")}
    if configured:
        return configured
    return set(agents if agents is not None else agent_map())


def allowed_actions() -> frozenset[str]:
    configured = {item.lower() for item in csv_env("NATIVE_HOST_ALLOWED_ACTIONS")}
    if configured:
        return frozenset(BUILTIN_ACTIONS & configured)
    return BUILTIN_ACTIONS


def allowed_callback_suffixes() -> set[str]:
    suffixes = {item.lower().lstrip(".") for item in csv_env("NATIVE_HOST_ALLOWED_CALLBACK_SUFFIXES")}
    suffixes.add(DEFAULT_HOST_SUFFIX)
    return {suffix for suffix in suffixes if suffix}


def hostname_allowed(hostname: str | None, suffixes: set[str]) -> bool:
    name = (hostname or "").rstrip(".").lower()
    return any(name == suffix or name.endswith("." + suffix) for suffix in suffixes)


def marker_for(token: str, job_id: str) -> str:
    return f"wraith-native:{job_id}:{token}"


def normalize_actions(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        items: list[object] = value.split(",")
    elif isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        raise PolicyError("invalid actions")
    actions: list[str] = []
    for item in items:
        if not isinstance(item, str) or not item.strip():
            continue
        action = item.strip().lower()
        if action not in actions:
            actions.append(action)
    if len(actions) > len(BUILTIN_ACTIONS):
        raise PolicyError("too many actions")
    return actions


def cleanup_requested(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, dict):
        for key in ("enabled", "remove", "cleanup"):
            if key in value and value[key] is False:
                return False
        return bool(value)
    if isinstance(value, (list, tuple, set, str)):
        return bool(value)
    return False


def validate_job(raw: dict) -> dict:
    token = raw.get("token")
    if not isinstance(token, str) or not TOKEN_MIN_LENGTH <= len(token) <= TOKEN_MAX_LENGTH:
        raise PolicyError("invalid token")

    host_id = raw.get("host_id")
    if not isinstance(host_id, str) or not HOST_ID_RE.fullmatch(host_id.strip().lower()):
        raise PolicyError("invalid host_id")
    host_id = host_id.strip().lower()

    job_id = raw.get("job_id") or uuid.uuid4().hex
    if not isinstance(job_id, str) or not JOB_ID_RE.fullmatch(job_id):
        raise PolicyError("invalid job_id")

    actions = normalize_actions(raw.get("actions"))
    if not actions:
        raise PolicyError("no actions requested")
    permitted = allowed_actions()
    for action in actions:
        if action not in permitted:
            raise PolicyError("action not allowed")

    cleanup = cleanup_requested(raw.get("cleanup"))
    if not cleanup and any(action in FILE_CREATING_ACTIONS for action in actions):
        raise PolicyError("cleanup required")

    ttl = raw.get("ttl_seconds")
    if ttl is None:
        ttl = 3600
    if isinstance(ttl, bool):
        raise PolicyError("invalid ttl_seconds")
    try:
        ttl = int(ttl)
    except (TypeError, ValueError):
        raise PolicyError("invalid ttl_seconds") from None
    if ttl < 1 or ttl > 3600:
        raise PolicyError("ttl out of range")

    callback = raw.get("callback_url")
    if callback not in (None, ""):
        if not isinstance(callback, str):
            raise PolicyError("invalid callback_url")
        parts = urlsplit(callback)
        if (
            parts.scheme not in {"http", "https"}
            or not hostname_allowed(parts.hostname, allowed_callback_suffixes())
            or parts.username
            or parts.password
        ):
            raise PolicyError("callback_url not allowed")

    target = raw.get("target_url")
    if target not in (None, ""):
        if not isinstance(target, str):
            raise PolicyError("invalid target_url")
        parts = urlsplit(target)
        hostname = (parts.hostname or "").rstrip(".").lower()
        expected = f"{host_id}.{DEFAULT_HOST_SUFFIX}"
        canonical_peer = hostname.endswith("." + DEFAULT_HOST_SUFFIX) and host_id in hostname.split(".")
        if (
            parts.scheme != "https"
            or parts.username
            or parts.password
            or (hostname != expected and not canonical_peer)
        ):
            raise PolicyError("target_url not allowed")

    agents = agent_map()
    if host_id not in allowed_host_ids(agents):
        raise PolicyError("host_id not allowed")
    if host_id not in agents:
        raise PolicyError("no agent configured for host_id")

    return {
        "job_id": job_id,
        "host_id": host_id,
        "token": token,
        "actions": actions,
        "cleanup": cleanup,
        "target_url": target or canonical_target_url(host_id),
        "callback_url": callback,
        "ttl_seconds": ttl,
        "agent_url": agents[host_id],
    }
