import hmac

from fastapi import Header, HTTPException, status
from .config import settings

# Same constant-time comparison as every other service's auth module. The
# details are documented in graph_db/app/auth.py; the short version is that
# `!=` on two strings returns at the first differing byte, which leaks the token
# one byte at a time.
def _bearer_matches(authorization: str | None, expected_token: str) -> bool:
    if not authorization or not expected_token:
        return False
    presented = authorization.encode("utf-8")
    expected = f"Bearer {expected_token}".encode("utf-8")
    if len(presented) != len(expected):
        return False
    return hmac.compare_digest(presented, expected)


async def require_admin_token(authorization: str = Header(None)):
    """Gate for the assessment route.

    POST reads the entire investigation graph through Graph DB and writes the
    result into this service's cache, so it is mutating here even though it is
    a read upstream. GET is left open because it only serves a cached report.
    """
    if not _bearer_matches(authorization, settings.ADMIN_API_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing admin token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return "admin"