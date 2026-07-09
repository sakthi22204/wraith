import pytest
import re
from mcp_servers.common.base_server import BaseSecurityServer

def test_regex_trailing_newline_bypass():
    server = BaseSecurityServer("test")

    # Normal valid targets
    server.validate_target("example.com")
    server.validate_target("127.0.0.1")
    server.validate_target("http://localhost:8080/api")

    # Trailing newline bypass attempt
    with pytest.raises(ValueError) as exc:
        server.validate_target("example.com\n")
    assert "command injection" in str(exc.value)

    # Complex bypass attempt
    with pytest.raises(ValueError) as exc:
        server.validate_target("example.com\n; rm -rf /")
    assert "command injection" in str(exc.value)

def test_metacharacter_rejection():
    server = BaseSecurityServer("test")

    metachars = [";", "|", "&", ">", "<", "$", "(", ")", "`", "*", "?"]
    for char in metachars:
        with pytest.raises(ValueError):
            server.validate_target(f"example.com{char}")
