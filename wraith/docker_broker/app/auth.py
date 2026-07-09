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
    # Extract caller identity from token or just return a generic 'authenticated_service'
    # For now, we'll just return the token itself as a simple identity placeholder
    # or the user can pass a 'caller' field in the request.
    return "authenticated_service"
