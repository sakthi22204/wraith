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

def test_new_recon_tool_commands_whitelisted():
    # dnsx
    validate_container_spec({
        "image": "projectdiscovery/dnsx:latest",
        "command": ["-d", "example.com"]
    })
    # nmap
    validate_container_spec({
        "image": "instrumentisto/nmap:latest",
        "command": ["-T4", "example.com"]
    })
    # tlsx
    validate_container_spec({
        "image": "projectdiscovery/tlsx:latest",
        "command": ["-u", "example.com"]
    })
    # ffuf
    validate_container_spec({
        "image": "ffuf/ffuf:latest",
        "command": ["-u", "http://example.com/FUZZ", "-w", "/wordlists/common.txt", "-json"]
    })
    # kiterunner
    validate_container_spec({
        "image": "kiterunner:latest",
        "command": ["kb", "scan", "http://example.com/api", "-o", "json"]
    })
    # linkfinder
    validate_container_spec({
        "image": "linkfinder:latest",
        "command": ["-i", "http://example.com", "-o", "cli"]
    })
    # secretfinder
    validate_container_spec({
        "image": "secretfinder:latest",
        "command": ["-e", "http://example.com", "-o", "cli"]
    })
    # trufflehog
    validate_container_spec({
        "image": "trufflesecurity/trufflehog:latest",
        "command": ["git", "http://example.com"]
    })
    # gittools
    validate_container_spec({
        "image": "gittools:latest",
        "command": ["-u", "http://example.com"]
    })
    # wpscan
    validate_container_spec({
        "image": "wpscanteam/wpscan:latest",
        "command": ["--url", "http://example.com"]
    })
    # cloud_enum
    validate_container_spec({
        "image": "cloud_enum:latest",
        "command": ["-k", "example"]
    })

def test_bare_domain_tools_validation():
    # gau and waybackurls safe domains accepted
    for img in ["lc/gau:latest", "tomnomnom/waybackurls:latest"]:
        validate_container_spec({
            "image": img,
            "command": ["example.com"]
        })

        # Rejected flag smuggling
        with pytest.raises(HTTPException) as exc:
            validate_container_spec({
                "image": img,
                "command": ["-h"]
            })
        assert exc.value.status_code == 403

        # Rejected multiple arguments
        with pytest.raises(HTTPException) as exc:
            validate_container_spec({
                "image": img,
                "command": ["example.com", "extra_arg"]
            })
        assert exc.value.status_code == 403

        # Rejected shell metacharacters
        with pytest.raises(HTTPException) as exc:
            validate_container_spec({
                "image": img,
                "command": ["example.com; rm -rf /"]
            })
        assert exc.value.status_code == 403


def test_bare_domain_tools_allow_safe_docker_service_with_port():
    for img in ["lc/gau:latest", "tomnomnom/waybackurls:latest"]:
        validate_container_spec({
            "image": img,
            "command": ["juice_shop:3000"]
        })

def test_invalid_command_rejected():
    spec_invalid = {
        "image": "projectdiscovery/httpx:latest",
        "command": ["rm", "-rf", "/"]
    }
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec_invalid)
    assert exc.value.status_code == 403


def test_only_internal_recon_network_is_allowed():
    validate_container_spec({
        "image": "projectdiscovery/httpx:latest",
        "command": ["-u", "http://juice_shop:3000"],
        "network": "wraith_wraith_internal",
    })

    with pytest.raises(HTTPException) as exc:
        validate_container_spec({
            "image": "projectdiscovery/httpx:latest",
            "command": ["-u", "http://juice_shop:3000"],
            "network": "other_network",
        })
    assert exc.value.status_code == 403
