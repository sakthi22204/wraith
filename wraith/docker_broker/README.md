# Wraith — Phase 6: Isolation Hardening (Docker Broker)

The Docker Broker is a security proxy that sits between services needing to spawn containers (like the Recon Orchestrator) and the Docker daemon. It enforces a strict whitelist of images and forbids dangerous container configurations.

## 🛡️ Security Boundaries

The broker intercepts all container creation requests and validates them:
1. **Image Whitelist**: Only images with exact tags listed in `app/whitelist.py` are allowed.
2. **No Host Access**: Bind mounts are strictly forbidden. Only named volumes (not currently used) are permitted.
3. **No Privileged Mode**: Containers cannot be started with `--privileged`.
4. **No Host Networking**: `network_mode="host"` is rejected.
5. **No Added Capabilities**: `cap_add` is forbidden.

## Whitelist Configuration

Approved images are defined in `wraith/docker_broker/app/whitelist.py`:

```python
ALLOWED_IMAGES = [
    "projectdiscovery/subfinder:latest",
    "projectdiscovery/httpx:latest",
    "projectdiscovery/katana:latest",
    "projectdiscovery/naabu:latest",
    "kalilinux/kali-rolling:latest"
]
```

To add a new tool:
1. Add the exact image name and tag to `ALLOWED_IMAGES`.
2. Restart the `docker_broker` service.

## API Usage

The broker exposes a subset of the Docker API:
- `POST /api/v1/containers`: Create and start a container (takes a spec).
- `POST /api/v1/containers/{id}/wait`: Wait for container completion.
- `GET /api/v1/containers/{id}/logs`: Retrieve container output.
- `DELETE /api/v1/containers/{id}`: Force remove a container.

## Audit Logging
All requests are logged to stdout with an `[ALLOWED]` or `[REJECTED]` prefix, including the reason for any rejections.

## Running Tests
```bash
cd wraith/docker_broker
PYTHONPATH=. pytest
```
