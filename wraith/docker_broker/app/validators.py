import re
import ipaddress
from fastapi import HTTPException
from .whitelist import (
    ALLOWED_IMAGES,
    ALLOWED_COMMANDS_PER_IMAGE,
    ALLOWED_NAMED_VOLUMES,
)
from .config import settings


# Every key the broker is willing to forward to containers.run().
#
# This list is an allowlist, not a blocklist, and that is the whole point. The
# broker holds the host docker socket, so anything it forwards is executed with
# host-equivalent authority. A blocklist can only refuse the escapes someone
# thought of, and the SDK's parameter space is far larger than any list: the
# previous version of this file named privileged, host networking and bind
# mounts, and silently passed through mounts, volumes_from, cgroupns,
# uts_mode, userns_mode, sysctls and the rest. `mounts` alone was a host-root
# path -- {"Type": "bind", "Source": "/", "Target": "/host"}.
#
# Every field recon_orchestrator actually sends is listed here, so closing the
# gap does not narrow what the recon pipeline can do.
ALLOWED_SPEC_KEYS = frozenset({
    "image",
    "command",
    "mem_limit",
    "cpu_quota",
    "network",
    "detach",
    "remove",
    "volumes",
    "extra_hosts",
    "environment",
})

# Refused outright because each one reaches outside the container the broker
# starts: into the host filesystem, into another container's namespaces, or
# into the host's own namespaces. The value does not matter -- `network_mode:
# "bridge"` shares a namespace just as much as `network_mode: "host"` does, and
# the old check only compared against the literal string "host".
NAMESPACE_ESCAPE_KEYS = {
    "privileged": "Privileged mode is forbidden.",
    "network_mode": "Host network mode is forbidden.",
    "pid_mode": "Host PID mode is forbidden.",
    "ipc_mode": "Host IPC mode is forbidden.",
    "security_opt": "Security options are forbidden.",
    "devices": "Device mapping is forbidden.",
    "cap_add": "Adding capabilities is forbidden.",
    "mounts": (
        "'mounts' is refused: it is how a host filesystem is handed to the "
        "container (a bind mount of / is a host-root path), and the broker has "
        "no host path to mount. Use an approved named volume read-only."
    ),
    "volumes_from": (
        "'volumes_from' is refused: it joins the container to another "
        "container's namespaces, inheriting that container's mounts."
    ),
    "cgroupns": "'cgroupns' is refused: it shares the host's control groups.",
    "uts_mode": "'uts_mode' is refused: it shares the host's hostname namespace.",
    "userns_mode": "'userns_mode' is refused: it disables user-namespace isolation.",
    "isolation": "'isolation' is refused: it selects the container's isolation mode.",
    "init_path": "'init_path' is refused: it runs an arbitrary binary as the container's init.",
    "group_add": "'group_add' is refused: it changes the container's group set.",
    "sysctls": "'sysctls' is refused: it writes kernel parameters.",
    "lxc_conf": "'lxc_conf' is refused: it configures LXC-level container options.",
}


def _is_safe_host_or_host_port(value: str) -> bool:
    """Allow a DNS name or Docker service name with an optional TCP port."""
    host, separator, port = value.partition(":")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]*", host):
        return False
    if not separator:
        return True
    return port.isdigit() and 1 <= int(port) <= 65535

def validate_container_spec(spec: dict):
    image = spec.get("image")
    if not image or image not in ALLOWED_IMAGES:
        raise HTTPException(status_code=403, detail=f"Image {image} is not in the whitelist.")

    # Anything outside the allowlist is refused before it is looked at again.
    # Naming the escape keys first is not about priority -- both raise -- it is
    # so an operator reading a refusal learns that the request tried to share a
    # namespace rather than merely misspelling an option.
    for key, reason in NAMESPACE_ESCAPE_KEYS.items():
        if key in spec:
            raise HTTPException(status_code=403, detail=reason)
    unknown = set(spec) - ALLOWED_SPEC_KEYS
    if unknown:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Unrecognized container spec field(s) {sorted(unknown)}. "
                f"The broker only forwards: {', '.join(sorted(ALLOWED_SPEC_KEYS))}."
            ),
        )

    # Command validation
    command = spec.get("command")
    if command and image in ALLOWED_COMMANDS_PER_IMAGE:
        base_cmd = command[0]
        allowed_cmds = ALLOWED_COMMANDS_PER_IMAGE[image]
        if allowed_cmds is None:
            # Special case for bare domain tools like gau/waybackurls
            # Rule: only exactly 1 argument is allowed, and it cannot start with a flag (-) or contain shell metacharacters.
            if len(command) != 1:
                raise HTTPException(status_code=403, detail="Multiple arguments are forbidden for this tool.")
            if base_cmd.startswith("-"):
                raise HTTPException(status_code=403, detail="Flags/options are forbidden for this tool.")
            if not _is_safe_host_or_host_port(base_cmd):
                raise HTTPException(status_code=403, detail=f"Invalid positional argument/domain: {base_cmd}")
        else:
            if base_cmd not in allowed_cmds:
                raise HTTPException(status_code=403, detail=f"Command {command} is not allowed for image {image}.")

    # Only the internal recon network may be joined. This used to be checked
    # after the namespace denials and only for the literal value "host", which
    # left network_mode on any other string unchecked; NAMESPACE_ESCAPE_KEYS
    # now refuses the key outright.
    network = spec.get("network")
    if network and network != settings.RECON_DOCKER_NETWORK:
        raise HTTPException(status_code=403, detail="Only the internal recon network is allowed.")

    # Volumes: named volumes only. The only volume in production use is the
    # mitmproxy CA (recon_orchestrator/app/tools/proxy.py), so there is no host
    # path mount to preserve and nothing to narrow a path allowlist against.
    # The old check refused host paths by their leading "/" or "." and had a
    # carve-out keyed on "common.txt" appearing anywhere in the path, which
    # /etc/shadow/common.txt rode straight through.
    volumes = spec.get("volumes")
    if volumes:
        if not isinstance(volumes, dict):
            raise HTTPException(
                status_code=403,
                detail="volumes must be a mapping of named volume to mount spec.")
        for name, vol_spec in volumes.items():
            if name not in ALLOWED_NAMED_VOLUMES:
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"Volume '{name}' is not an approved named volume. "
                        f"Bind mounts (host filesystem access) are forbidden; "
                        f"approved volumes: {', '.join(sorted(ALLOWED_NAMED_VOLUMES))}."
                    ),
                )
            if not isinstance(vol_spec, dict) or vol_spec.get("mode") != "ro":
                raise HTTPException(
                    status_code=403,
                    detail=f"Volume '{name}' must be mounted read-only.",
                )

    # extra_hosts: mapping of hostname -> IP injected into the tool container's /etc/hosts.
    # Allows Go-based tools (e.g. naabu) to resolve Docker-internal single-label service
    # names that the embedded DNS resolver does not answer for pure-Go lookups.
    extra_hosts = spec.get("extra_hosts")
    if extra_hosts:
        if not isinstance(extra_hosts, dict):
            raise HTTPException(status_code=403, detail="extra_hosts must be a mapping of hostname to IP.")
        for host, ip in extra_hosts.items():
            if not isinstance(host, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]*", host):
                raise HTTPException(status_code=403, detail=f"Invalid hostname in extra_hosts: {host}")
            if not isinstance(ip, str):
                raise HTTPException(status_code=403, detail=f"Invalid IP in extra_hosts for {host}: {ip}")
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                raise HTTPException(status_code=403, detail=f"Invalid IP in extra_hosts for {host}: {ip}")
