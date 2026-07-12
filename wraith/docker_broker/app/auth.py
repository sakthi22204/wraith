from fastapi import Header, HTTPException, status
from .config import settings

async def require_broker_token(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing broker token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.replace("Bearer ", "")

    if token == settings.RECON_ORCHESTRATOR_TOKEN:
        return "recon_orchestrator"
    if token == settings.ACTIVE_EXPLOIT_RUNNER_TOKEN:
        return "active_exploit_runner"

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid broker token",
        headers={"WWW-Authenticate": "Bearer"},
    )
