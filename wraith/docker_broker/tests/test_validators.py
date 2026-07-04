import pytest
from fastapi import HTTPException
from app.validators import validate_container_spec

def test_whitelist_rejection():
    spec = {"image": "malicious/image:latest"}
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec)
    assert exc.value.status_code == 403
    assert "whitelist" in exc.value.detail

def test_bind_mount_rejection():
    spec = {
        "image": "projectdiscovery/subfinder:latest",
        "volumes": {"/etc/passwd": {"bind": "/mnt/passwd", "mode": "rw"}}
    }
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec)
    assert "Bind mounts" in exc.value.detail

def test_privileged_mode_rejection():
    spec = {
        "image": "projectdiscovery/subfinder:latest",
        "privileged": True
    }
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec)
    assert "Privileged mode" in exc.value.detail

def test_host_network_rejection():
    spec = {
        "image": "projectdiscovery/subfinder:latest",
        "network_mode": "host"
    }
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec)
    assert "Host network mode" in exc.value.detail

def test_cap_add_rejection():
    spec = {
        "image": "projectdiscovery/subfinder:latest",
        "cap_add": ["SYS_ADMIN"]
    }
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec)
    assert "capabilities" in exc.value.detail

def test_allowed_spec():
    spec = {
        "image": "projectdiscovery/subfinder:latest",
        "command": ["-d", "example.com"],
        "mem_limit": "512m"
    }
    # Should not raise
    validate_container_spec(spec)
