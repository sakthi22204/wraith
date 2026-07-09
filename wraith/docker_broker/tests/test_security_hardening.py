import pytest
from fastapi import HTTPException
from app.validators import validate_container_spec

def test_host_pid_mode_rejection():
    spec = {
        "image": "projectdiscovery/subfinder:latest",
        "pid_mode": "host"
    }
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec)
    assert "Host PID mode" in exc.value.detail

def test_host_ipc_mode_rejection():
    spec = {
        "image": "projectdiscovery/subfinder:latest",
        "ipc_mode": "host"
    }
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec)
    assert "Host IPC mode" in exc.value.detail

def test_security_opt_rejection():
    spec = {
        "image": "projectdiscovery/subfinder:latest",
        "security_opt": ["seccomp=unconfined"]
    }
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec)
    assert "Security options" in exc.value.detail

def test_devices_rejection():
    spec = {
        "image": "projectdiscovery/subfinder:latest",
        "devices": ["/dev/sda:/dev/sda"]
    }
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec)
    assert "Device mapping" in exc.value.detail

def test_command_validation_pd_tools():
    # Valid
    spec = {
        "image": "projectdiscovery/subfinder:latest",
        "command": ["-d", "example.com"]
    }
    validate_container_spec(spec)

    # Invalid
    spec = {
        "image": "projectdiscovery/subfinder:latest",
        "command": ["ls", "/etc"]
    }
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec)
    assert "Command" in exc.value.detail

def test_command_validation_kali():
    # Valid
    spec = {
        "image": "kalilinux/kali-rolling:latest",
        "command": ["nmap", "-v", "example.com"]
    }
    validate_container_spec(spec)

    # Invalid
    spec = {
        "image": "kalilinux/kali-rolling:latest",
        "command": ["bash", "-c", "whoami"]
    }
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec)
    assert "Command" in exc.value.detail
