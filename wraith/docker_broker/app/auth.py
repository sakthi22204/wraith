from fastapi import Header, HTTPException, status
from .config import settings

async def require_broker_token(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing broker token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if authorization == f"Bearer {settings.RECON_BROKER_TOKEN}":
        return "recon_orchestrator"

    if authorization == f"Bearer {settings.EXPLOIT_RUNNER_BROKER_TOKEN}":
        return "active_exploit_runner"

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid broker token",
        headers={"WWW-Authenticate": "Bearer"},
    )
