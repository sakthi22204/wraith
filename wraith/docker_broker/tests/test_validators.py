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

def test_extra_hosts_allowed():
    spec = {
        "image": "projectdiscovery/naabu:latest",
        "command": ["-host", "juice_shop:3000", "-json", "-silent"],
        "extra_hosts": {"juice_shop": "172.18.0.3"}
    }
    # Should not raise
    validate_container_spec(spec)

def test_extra_hosts_rejects_bad_hostname():
    spec = {
        "image": "projectdiscovery/naabu:latest",
        "command": ["-host", "juice_shop:3000"],
        "extra_hosts": {"juice_shop;rm -rf /": "172.18.0.3"}
    }
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec)
    assert exc.value.status_code == 403
    assert "extra_hosts" in exc.value.detail

def test_extra_hosts_rejects_bad_ip():
    spec = {
        "image": "projectdiscovery/naabu:latest",
        "command": ["-host", "juice_shop:3000"],
        "extra_hosts": {"juice_shop": "localhost"}
    }
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec)
    assert exc.value.status_code == 403
    assert "Invalid IP" in exc.value.detail

def test_extra_hosts_rejects_non_dict():
    spec = {
        "image": "projectdiscovery/naabu:latest",
        "command": ["-host", "juice_shop:3000"],
        "extra_hosts": ["juice_shop=172.18.0.3"]
    }
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec)
    assert exc.value.status_code == 403
    assert "extra_hosts" in exc.value.detail


# The validator used to be a blocklist, so anything it did not name was
# accepted and forwarded to the Docker SDK by proxy.py's **spec. The broker
# holds the host docker socket, which makes each of these below a host-root
# path rather than a sandbox escape: they are all ways to hand the container
# access to the host or to another container that has it.
NAMESPACE_KEYS = [
    "mounts",
    "volumes_from",
    "cgroupns",
    "uts_mode",
    "userns_mode",
    "ipc_mode",
    "pid_mode",
    "network_mode",
    "isolation",
    "init_path",
    "group_add",
    "sysctls",
    "lxc_conf",
    "security_opt",
    "devices",
    "cap_add",
    "privileged",
]


@pytest.mark.parametrize("key", NAMESPACE_KEYS)
def test_namespace_sharing_keys_are_refused(key):
    """A host bind mount is a direct host-root path.

    ``mounts`` was never inspected, and docker-py forwards it verbatim into
    HostConfig, so ``{"Type": "bind", "Source": "/", "Target": "/host"}``
    reached the Engine API unmodified despite the blocklist.
    """
    spec = {"image": "projectdiscovery/subfinder:latest", key: {"Type": "bind"}}
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec)
    assert exc.value.status_code == 403


def test_host_bind_mount_through_mounts_key_is_refused():
    """The exact payload that was exploitable."""
    spec = {
        "image": "projectdiscovery/httpx:latest",
        "command": ["https://example.com"],
        "mounts": [{"Type": "bind", "Source": "/", "Target": "/host"}],
    }
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec)
    assert exc.value.status_code == 403
    assert "mounts" in exc.value.detail.lower()


@pytest.mark.parametrize("key", ["volumes_from", "cgroupns", "uts_mode"])
def test_namespace_sharing_keys_are_refused_with_a_specific_value(key):
    """A bare key is only refused if the check looks at the key; these values
    are the ones that make the attack work."""
    values = {
        "volumes_from": "wraith-postgres-1",
        "cgroupns": "host",
        "uts_mode": "host",
    }
    spec = {"image": "projectdiscovery/subfinder:latest", key: values[key]}
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec)
    assert exc.value.status_code == 403


def test_unknown_spec_keys_are_refused():
    """An allowlist cannot be satisfied by a key nobody thought of.

    Every unrecognised key is refused outright rather than ignored, so the
    validator and the SDK's parameter space cannot drift apart silently.
    """
    spec = {"image": "projectdiscovery/subfinder:latest", "not_a_real_option": 1}
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec)
    assert exc.value.status_code == 403
    assert "not_a_real_option" in exc.value.detail


def test_every_field_the_orchestrator_sends_is_still_accepted():
    """The allowlist must cover what recon_orchestrator actually sends, or the
    fix breaks the pipeline it is meant to protect."""
    spec = {
        "image": "projectdiscovery/subfinder:latest",
        "command": ["-d", "example.com"],
        "mem_limit": "512m",
        "cpu_quota": 50000,
        "network": "wraith_wraith_internal",
        "detach": True,
        "remove": False,
        # The proxy CA is a NAMED volume, which is the only kind in production use.
        "volumes": {"mitmproxy_ca": {"bind": "/etc/mitmproxy-ca", "mode": "ro"}},
        "extra_hosts": {"juice_shop": "172.18.0.3"},
        "environment": {"FOO": "bar"},
    }
    validate_container_spec(spec)


@pytest.mark.parametrize(
    "host_path",
    ["/etc", "../../etc", "../secrets", "./secrets", "/etc/shadow", "/root/.ssh"],
)
def test_host_path_volumes_are_refused(host_path):
    """No host path may be mounted at all.

    Production only ever mounts the named CA volume (tools/proxy.py), so there is
    no legitimate host-path mount to preserve and nothing to narrow an allowlist
    against. A relative path or one containing '..' is a bind mount to somewhere
    the caller chose, which is why the check is on the resolved shape rather
    than a leading '/'."""
    spec = {
        "image": "projectdiscovery/subfinder:latest",
        "volumes": {host_path: {"bind": "/wordlists", "mode": "ro"}},
    }
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec)
    assert exc.value.status_code == 403


def test_unknown_named_volume_is_refused():
    """A named volume is still host-adjacent state, so the set is closed."""
    spec = {
        "image": "projectdiscovery/subfinder:latest",
        "volumes": {"some_other_volume": {"bind": "/x", "mode": "ro"}},
    }
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec)
    assert exc.value.status_code == 403


def test_common_txt_substring_special_case_is_gone():
    """The old exemption keyed on "common.txt" appearing anywhere in the host
    path, so /etc/shadow/common.txt rode through a bind-mount ban."""
    spec = {
        "image": "projectdiscovery/subfinder:latest",
        "volumes": {
            "/etc/shadow/common.txt": {"bind": "/wordlists/common.txt", "mode": "ro"}
        },
    }
    with pytest.raises(HTTPException) as exc:
        validate_container_spec(spec)
    assert exc.value.status_code == 403
