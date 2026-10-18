from datetime import datetime
from unittest.mock import AsyncMock

import pytest

from app.repository import Neo4jRepository, scope_host
from app.schema import InvestigationCreate


@pytest.mark.parametrize(
    "target,expected",
    [
        ("example.com", "example.com"),
        ("Example.COM", "example.com"),
        ("https://example.com", "example.com"),
        ("http://juice_shop:3000", "juice_shop"),
        ("http://juice_shop:3000/path?x=1", "juice_shop"),
        ("example.com:8443", "example.com"),
        ("https://user:pass@example.com/a/b", "example.com"),
        ("192.168.1.10", "192.168.1.10"),
        ("https://192.168.1.10:8080/x", "192.168.1.10"),
        ("  ebms.co.in  ", "ebms.co.in"),
        ("", ""),
    ],
)
def test_scope_host(target, expected):
    assert scope_host(target) == expected


@pytest.mark.asyncio
async def test_create_investigation_stores_normalized_scope():
    session = AsyncMock()
    result = AsyncMock()
    result.single.return_value = {
        "i": {
            "id": "inv-1",
            "name": "juice",
            "target": "http://juice_shop:3000",
            "scope_domains": ["juice_shop"],
            "platform": "automatic",
            "aggressive": True,
            "created_at": datetime.utcnow(),
        }
    }
    session.run.return_value = result

    repo = Neo4jRepository(session)
    inv = await repo.create_investigation(
        InvestigationCreate(name="juice", target="http://juice_shop:3000")
    )

    assert session.run.call_args.kwargs["scope_domains"] == ["juice_shop"]
    assert inv.scope_domains == ["juice_shop"]
