import pytest
from app.validators import validate_container_spec
from fastapi import HTTPException

def test_recon_tool_commands_whitelisted():
    # Test subfinder
    spec_subfinder = {
        "image": "projectdiscovery/subfinder:latest",
        "command": ["-d", "example.com", "-json"]
    }
    validate_container_spec(spec_subfinder) # Should not raise

    # Test httpx
    spec_httpx = {
        "image": "projectdiscovery/httpx:latest",
        "command": ["-u", "example.com", "-json", "-silent"]
    }
    validate_container_spec(spec_httpx) # Should not raise

    # Test naabu
    spec_naabu = {
        "image": "projectdiscovery/naabu:latest",
        "command": ["-host", "example.com", "-json", "-silent"]
    }
    validate_container_spec(spec_naabu) # Should not raise

    # Test katana
    spec_katana = {
        "image": "projectdiscovery/katana:latest",
        "command": ["-u", "example.com", "-json", "-silent"]
    }
    validate_container_spec(spec_katana) # Should not raise

def test_httpx_list_still_allowed():
    spec_httpx_list = {
        "image": "projectdiscovery/httpx:latest",
        "command": ["-list", "urls.txt", "-json"]
    }
    validate_container_spec(spec_httpx_list) # Should not raise

def test_invalid_command_rejected():
    spec_invalid = {
        "image": "projectdiscovery/httpx:latest",
        "command": ["rm", "-rf", "/"]
    }
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec_invalid)
    assert exc.value.status_code == 403
