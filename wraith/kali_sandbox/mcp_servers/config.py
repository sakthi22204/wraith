"""Settings the sandbox needs to enforce its own gates."""
import os
from dataclasses import dataclass


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


settings = Settings()
