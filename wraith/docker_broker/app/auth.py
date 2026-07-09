from fastapi import Header, HTTPException, status
from .config import settings

async def require_broker_token(authorization: str = Header(None)):
    expected_token = f"Bearer {settings.DOCKER_BROKER_TOKEN}"
    if authorization != expected_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing broker token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # For now, return a generic identifier that represents an authenticated service.
    # In a more advanced setup, this could be derived from sub-tokens or headers.
    return "authenticated_service"
