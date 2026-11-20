"""Settings the sandbox needs to enforce its own gates."""
import os
from dataclasses import dataclass

# Values that must never be accepted as a live secret, because they are already
# published in docker-compose.yml and in this repository. Kept identical to the
# other services' list so that re-introducing a default fails the startup test
# rather than passing review.
KNOWN_INSECURE_SECRETS = frozenset({
    "",
    "dev-token-change-me",
    "dev-exploit-token",
    "dev-recon-token",
    "wraith-dev-gate-secret",
    "password",
    "changeme",
    "change-me",
    "secret",
})


def _env_value(name: str, default: str) -> str:
    for key in (name, "WRAITH_" + name):
        raw = os.getenv(key)
        if raw is not None and str(raw).strip():
            return str(raw).strip()
    return default


def _env_int(name: str, default: int) -> int:
    raw = _env_value(name, "")
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = _env_value(name, "")
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    # Same values the runner uses. Without these the sandbox cannot read the
    # killswitch or the scope rules, and the gate would have nothing to check.
    REDIS_URL: str = os.getenv("REDIS_URL", "")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "")
    # Shared with active_exploit_runner. Requests without a matching signature
    # are refused, so this must be identical on both sides and unset means
    # closed, not open.
    GATE_SECRET: str = os.getenv("WRAITH_GATE_SECRET", os.getenv("GATE_SECRET", ""))
    # UNSAFE: when true, gate_request() and the dangerous-caller floor are
    # skipped entirely. Mirrors the flag in the runner and exploit_agent.
    FULL_TOOL_ACCESS: bool = os.getenv(
        "WRAITH_FULL_TOOL_ACCESS", os.getenv("FULL_TOOL_ACCESS", "0")
    ).strip().lower() in ("1", "true", "yes", "on")

    OOB_CALLBACK_HOST: str = _env_value("OOB_CALLBACK_HOST", "127.0.0.1")
    OOB_CALLBACK_PORT: int = _env_int("OOB_CALLBACK_PORT", 8091)
    OOB_DNS_PORT: int = _env_int("OOB_DNS_PORT", 5353)
    OOB_MAX_WAIT_SECONDS: float = _env_float("OOB_MAX_WAIT_SECONDS", 15.0)
    SMTP_CAPTURE_HOST: str = _env_value("SMTP_CAPTURE_HOST", "127.0.0.1")
    SMTP_CAPTURE_PORT: int = _env_int("SMTP_CAPTURE_PORT", 0)
    SMTP_ALLOWED_RECIPIENT_DOMAINS: str = _env_value(
        "SMTP_ALLOWED_RECIPIENT_DOMAINS", ".invalid"
    )
    NATIVE_HOST_BRIDGE_URL: str = _env_value("NATIVE_HOST_BRIDGE_URL", "")
    NATIVE_HOST_BRIDGE_TOKEN: str = _env_value("NATIVE_HOST_BRIDGE_TOKEN", "")
    NATIVE_HOST_PROBE_TIMEOUT: float = _env_float("NATIVE_HOST_PROBE_TIMEOUT", 5.0)


def validate_startup_secrets(cfg: "Settings" = None) -> None:
    """Refuse to start without a usable gate secret.

    The sandbox already fails closed per request: an absent secret means no
    grant can be verified, so every tool call is refused. Failing at startup
    instead makes the misconfiguration loud and immediate rather than a stream of
    403s that look like a target problem.
    """
    if cfg is None:
        cfg = settings
    # getattr, not cfg.GATE_SECRET: an object missing the field must read as
    # unset rather than raising, so a refactor that renames the field fails as a
    # refusal to start instead of an AttributeError traceback.
    value = (getattr(cfg, "GATE_SECRET", "") or "").strip()
    if not value:
        raise RuntimeError(
            "Refusing to start kali_sandbox: GATE_SECRET is empty. It is shared "
            "with active_exploit_runner and must be injected as "
            "WRAITH_GATE_SECRET; unset means every request is refused."
        )
    if value in KNOWN_INSECURE_SECRETS:
        raise RuntimeError(
            "Refusing to start kali_sandbox: GATE_SECRET is set to a value "
            f"published in this repository ({value!r}); generate a real secret "
            "and inject it"
        )


settings = Settings()
