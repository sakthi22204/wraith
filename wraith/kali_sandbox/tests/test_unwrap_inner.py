import pytest
from pydantic import BaseModel
from mcp_servers.main import unwrap_inner


class FakeStructured(BaseModel):
    findings: list = []


def test_unwrap_inner_returns_structured_payload():
    content = [{"type": "text", "text": "{\n  \"findings\": [],\n  \"raw_output\": \"\"\n}"}]
    structured = FakeStructured()
    result = unwrap_inner((content, structured))
    assert result is structured


def test_unwrap_inner_returns_dict_payload():
    structured = {"findings": []}
    result = unwrap_inner(([{"type": "text", "text": "{}"}], structured))
    assert result == structured


def test_unwrap_inner_non_tuple_passthrough():
    assert unwrap_inner("plain") == "plain"
    assert unwrap_inner(None) is None