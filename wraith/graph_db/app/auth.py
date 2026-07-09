from fastapi import Header, HTTPException, status
from .config import settings

async def require_admin_token(authorization: str = Header(None)):
    expected_token = f"Bearer {settings.ADMIN_API_TOKEN}"
    if authorization != expected_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing admin token",
            headers={"WWW-Authenticate": "Bearer"},
        )
