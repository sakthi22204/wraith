import hmac

from fastapi import Header, HTTPException, status
from .config import settings

# Constant-time comparison; see graph_db/app/auth.py for why `!=` on the full
# header string leaks the token prefix by prefix.
def _bearer_matches(authorization: str | None, expected_token: str) -> bool:
    if not authorization or not expected_token:
        return False
    presented = authorization.encode("utf-8")
    expected = f"Bearer {expected_token}".encode("utf-8")
    if len(presented) != len(expected):
        return False
    return hmac.compare_digest(presented, expected)


async def require_broker_token(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing broker token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Both branches must be evaluated, not short-circuited: returning on the
    # first match would make the response time depend on which token was right.
    if _bearer_matches(authorization, settings.RECON_BROKER_TOKEN):
        return "recon_orchestrator"

    if _bearer_matches(authorization, settings.EXPLOIT_RUNNER_BROKER_TOKEN):
        return "active_exploit_runner"

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid broker token",
        headers={"WWW-Authenticate": "Bearer"},
    )