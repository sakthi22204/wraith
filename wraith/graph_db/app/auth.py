import hmac

from fastapi import Header, HTTPException, status
from .config import settings


def _bearer_matches(authorization: str | None, expected_token: str) -> bool:
    """Constant-time check that the header is exactly ``Bearer <token>``.

    ``authorization == f"Bearer {expected}"`` was used here, and in every other
    service's auth module. Python's string equality returns at the first
    differing byte, so it leaks how much of a guessed token was correct; over a
    network that turns a brute-force-resistant secret into a linear search.
    ``hmac.compare_digest`` inspects every byte regardless of where they differ.

    Length is compared first, and a length mismatch is not a secret either: the
    length of the correct token is already observable from the 401/200 split.
    """
    if not authorization or not expected_token:
        return False
    presented = authorization.encode("utf-8")
    expected = f"Bearer {expected_token}".encode("utf-8")
    if len(presented) != len(expected):
        return False
    return hmac.compare_digest(presented, expected)


async def require_admin_token(authorization: str = Header(None)):
    if not _bearer_matches(authorization, settings.ADMIN_API_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing admin token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return "admin"