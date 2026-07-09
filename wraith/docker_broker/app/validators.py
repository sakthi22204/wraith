from fastapi import HTTPException
from .whitelist import ALLOWED_IMAGES, ALLOWED_COMMANDS_PER_IMAGE

def validate_container_spec(spec: dict):
    image = spec.get("image")
    if not image or image not in ALLOWED_IMAGES:
        raise HTTPException(status_code=403, detail=f"Image {image} is not in the whitelist.")

    # Command validation
    command = spec.get("command")
    if command and image in ALLOWED_COMMANDS_PER_IMAGE:
        base_cmd = command[0]
        allowed_cmds = ALLOWED_COMMANDS_PER_IMAGE[image]
        # Command must start with one of the allowed commands/args
        if not any(base_cmd == allowed for allowed in allowed_cmds):
            raise HTTPException(status_code=403, detail=f"Command {command} is not allowed for image {image}.")

    # Forbidden features
    if spec.get("privileged"):
        raise HTTPException(status_code=403, detail="Privileged mode is forbidden.")

    if spec.get("network_mode") == "host":
        raise HTTPException(status_code=403, detail="Host network mode is forbidden.")

    if spec.get("pid_mode") == "host":
        raise HTTPException(status_code=403, detail="Host PID mode is forbidden.")

    if spec.get("ipc_mode") == "host":
        raise HTTPException(status_code=403, detail="Host IPC mode is forbidden.")

    if spec.get("security_opt"):
        raise HTTPException(status_code=403, detail="Security options are forbidden.")

    if spec.get("devices"):
        raise HTTPException(status_code=403, detail="Device mapping is forbidden.")

    if spec.get("cap_add"):
        raise HTTPException(status_code=403, detail="Adding capabilities is forbidden.")

    # Check for bind mounts
    volumes = spec.get("volumes", {})
    # For docker-py, volumes can be a dict: {host_path: {'bind': '/container_path', 'mode': 'rw'}}
    # or a list of strings
    if isinstance(volumes, dict):
        for host_path in volumes.keys():
            if host_path.startswith("/") or host_path.startswith("."):
                raise HTTPException(status_code=403, detail="Bind mounts (host filesystem access) are forbidden.")
    elif isinstance(volumes, list):
        for volume in volumes:
            if ":" in volume and (volume.startswith("/") or volume.startswith(".")):
                 raise HTTPException(status_code=403, detail="Bind mounts are forbidden.")
