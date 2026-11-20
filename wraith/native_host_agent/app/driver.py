from __future__ import annotations

import ctypes
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

AGENT_ACTIONS = frozenset(
    {
        "load_probe",
        "module_check",
        "log_write",
        "log_verify",
        "process_self",
        "cleanup",
    }
)
JOB_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
TOKEN_MIN_LENGTH = 12
TOKEN_MAX_LENGTH = 512
MAX_LOG_BYTES = 4096
MAX_PROBE_PATHS = 32
MAX_CLEANUP_FILES = 64


class DriverError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def canary_root() -> Path:
    configured = os.getenv("NATIVE_HOST_CANARY_DIR", "").strip()
    if not configured:
        configured = os.path.join(tempfile.gettempdir(), "wraith-native-canary")
    return Path(os.path.abspath(os.path.expanduser(configured)))


def is_contained(root: Path, candidate: Path) -> bool:
    root_path = os.path.abspath(str(root))
    candidate_path = os.path.abspath(str(candidate))
    try:
        return os.path.commonpath([root_path, candidate_path]) == root_path
    except ValueError:
        return False


def job_directory(root: Path, job_id: str) -> Path:
    safe = "".join(char if char.isalnum() or char in "_-." else "_" for char in job_id)[:64]
    safe = safe.strip(".")
    if not safe or safe in {".", ".."}:
        raise DriverError("invalid job_id")
    directory = root / safe
    if directory == root or not is_contained(root, directory):
        raise DriverError("invalid job_id")
    return directory


def marker_for(token: str, job_id: str) -> str:
    return f"wraith-native:{job_id}:{token}"


def normalize_actions(value: object) -> list[str]:
    if isinstance(value, str):
        items: list[object] = value.split(",")
    elif isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        raise DriverError("invalid actions")
    actions: list[str] = []
    for item in items:
        if not isinstance(item, str) or not item.strip():
            continue
        action = item.strip().lower()
        if action not in AGENT_ACTIONS:
            raise DriverError("unknown action")
        if action not in actions:
            actions.append(action)
    if not actions or len(actions) > len(AGENT_ACTIONS):
        raise DriverError("invalid actions")
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


def normalize_job(raw: dict) -> dict:
    token = raw.get("token")
    if not isinstance(token, str) or not TOKEN_MIN_LENGTH <= len(token) <= TOKEN_MAX_LENGTH:
        raise DriverError("invalid token")

    job_id = raw.get("job_id") or "job"
    if not isinstance(job_id, str) or not JOB_ID_RE.fullmatch(job_id):
        raise DriverError("invalid job_id")

    return {
        "job_id": job_id,
        "token": token,
        "actions": normalize_actions(raw.get("actions")),
        "cleanup": cleanup_requested(raw.get("cleanup")),
    }


def load_probe(marker: str) -> dict:
    result: dict[str, Any] = {
        "loaded": False,
        "unsupported": True,
        "marker": None,
        "checked_marker": marker,
        "path": None,
        "reason": "no probe library configured",
    }
    configured = os.getenv("NATIVE_HOST_PROBE_LIB", "").strip()
    if not configured:
        return result
    path = Path(os.path.abspath(os.path.expanduser(configured)))
    result["path"] = path.name
    if not path.is_file():
        result["reason"] = "probe library unavailable"
        return result
    try:
        ctypes.CDLL(str(path))
    except Exception:
        result["reason"] = "probe library could not be loaded"
        return result
    result["loaded"] = True
    result["unsupported"] = False
    result["marker"] = marker
    result.pop("reason", None)
    return result


def module_check(marker: str) -> dict:
    paths: list[str] = []
    try:
        with open("/proc/self/maps", "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                if marker not in line:
                    continue
                parts = line.split()
                if len(parts) >= 6:
                    paths.append(parts[-1])
                if len(paths) >= MAX_PROBE_PATHS:
                    break
    except OSError:
        return {"observed": False, "paths": [], "marker": marker, "source": "unsupported"}
    return {"observed": bool(paths), "paths": paths, "marker": marker, "source": "/proc/self/maps"}


def log_write(root: Path, directory: Path, marker: str, created: list[Path]) -> dict:
    if directory.is_symlink() or not is_contained(root, directory):
        raise DriverError("containment violation")
    directory.mkdir(parents=True, exist_ok=True)
    if directory.is_symlink() or not is_contained(root, directory):
        raise DriverError("containment violation")
    path = directory / "canary.log"
    if path.is_symlink() or not is_contained(root, path):
        raise DriverError("containment violation")
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(marker + "\n")
    created.append(path)
    return {"written": True, "path": str(path.relative_to(root)), "marker": marker}


def log_verify(root: Path, directory: Path, marker: str) -> dict:
    path = directory / "canary.log"
    relative = str(path.relative_to(root)) if is_contained(root, path) else ""
    verified = False
    content = ""
    if not path.is_symlink() and path.is_file() and is_contained(root, path):
        content = path.read_text(encoding="utf-8", errors="ignore")[:MAX_LOG_BYTES]
        verified = marker in content
    return {"verified": verified, "path": relative, "marker": marker, "content": content}


def process_self() -> dict:
    try:
        cmdline = Path("/proc/self/cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "ignore")[:512]
    except OSError:
        cmdline = ""
    return {"pid": os.getpid(), "name": Path(sys.argv[0]).name[:128], "cmdline": cmdline}


def cleanup_files(root: Path, directory: Path, created: list[Path], job_id: str, requested: bool) -> dict:
    if not requested:
        return {"removed": [], "removed_count": 0, "job_id": job_id}
    candidates = list(dict.fromkeys(created))
    if requested and not directory.is_symlink() and directory.is_dir() and is_contained(root, directory):
        try:
            for entry in sorted(directory.iterdir()):
                if entry.is_symlink() or entry.is_file():
                    candidates.append(entry)
        except OSError:
            pass
    removed: list[str] = []
    for path in candidates[:MAX_CLEANUP_FILES]:
        if path == root or not is_contained(root, path):
            continue
        try:
            if path.is_symlink() or path.is_file():
                path.unlink()
                removed.append(str(path.relative_to(root)))
        except OSError:
            continue
    directories = sorted({path.parent for path in candidates}, key=lambda item: len(item.parts), reverse=True)
    for directory in directories:
        if directory == root or not is_contained(root, directory) or directory.is_symlink():
            continue
        try:
            directory.rmdir()
        except OSError:
            pass
    return {"removed": removed, "removed_count": len(removed), "job_id": job_id}


def execute(raw: dict) -> dict:
    job = normalize_job(raw)
    root = canary_root()
    directory = job_directory(root, job["job_id"])
    marker = marker_for(job["token"], job["job_id"])
    evidence: dict[str, Any] = {}
    created: list[Path] = []

    for action in job["actions"]:
        if action == "load_probe":
            evidence[action] = load_probe(marker)
        elif action == "module_check":
            evidence[action] = module_check(marker)
        elif action == "log_write":
            evidence[action] = log_write(root, directory, marker, created)
        elif action == "log_verify":
            evidence[action] = log_verify(root, directory, marker)
        elif action == "process_self":
            evidence[action] = process_self()

    cleanup = cleanup_files(
        root,
        directory,
        created,
        job["job_id"],
        job["cleanup"] or "cleanup" in job["actions"],
    )
    evidence["marker"] = marker
    evidence["probe_marker"] = marker
    evidence["native_marker"] = marker
    for action in AGENT_ACTIONS:
        if action in evidence:
            evidence.setdefault(f"{action}_marker", marker)

    return {"evidence": evidence, "cleanup": cleanup}
