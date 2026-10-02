import hmac

from fastapi import Header, HTTPException, status
from .config import settings

# Same constant-time comparison as every other service's auth module; see
# graph_db/app/auth.py for why `!=` on two strings is not equivalent.
def _bearer_matches(authorization: str | None, expected_token: str) -> bool:
    if not authorization or not expected_token:
        return False
    presented = authorization.encode("utf-8")
    expected = f"Bearer {expected_token}".encode("utf-8")
    if len(presented) != len(expected):
        return False
    return hmac.compare_digest(presented, expected)


async def require_admin_token(authorization: str = Header(None)):
    """Gate for routes that start or cancel work.

    This is distinct from RECON_BROKER_TOKEN, which is what *this* service
    presents to the broker. It authorises callers into this service.
    """
    if not _bearer_matches(authorization, settings.ADMIN_API_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing admin token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return "admin"