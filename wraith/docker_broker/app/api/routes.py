from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional, Dict
from ..proxy import docker_proxy
from ..whitelist import ALLOWED_IMAGES
from ..auth import require_broker_token

router = APIRouter()

# In-memory ownership tracking
# container_id -> caller_identity
container_ownership: Dict[str, str] = {}

def verify_ownership(container_id: str, caller_id: str):
    owner = container_ownership.get(container_id)
    if not owner:
        # If we don't have it in memory (e.g. broker restarted), we might need to decide
        # whether to allow or deny. To be safe, we deny if it's not our container.
        raise HTTPException(status_code=404, detail="Container ownership not found")
    if owner != caller_id:
        raise HTTPException(status_code=403, detail="Not authorized to access this container")

@router.post("/containers")
async def create_container(spec: dict, caller_id: str = Depends(require_broker_token)):
    container_id = await docker_proxy.create_container(spec)
    container_ownership[container_id] = caller_id
    return {"container_id": container_id}

@router.post("/containers/{container_id}/wait")
async def wait_container(container_id: str, timeout: Optional[int] = None, caller_id: str = Depends(require_broker_token)):
    verify_ownership(container_id, caller_id)
    return await docker_proxy.wait_container(container_id, timeout)

@router.get("/containers/{container_id}/logs")
async def get_logs(container_id: str, caller_id: str = Depends(require_broker_token)):
    verify_ownership(container_id, caller_id)
    return {"logs": await docker_proxy.get_logs(container_id)}

@router.post("/containers/{container_id}/stop")
async def stop_container(container_id: str, caller_id: str = Depends(require_broker_token)):
    verify_ownership(container_id, caller_id)
    await docker_proxy.stop_container(container_id)
    return {"status": "stopped"}

@router.delete("/containers/{container_id}")
async def remove_container(container_id: str, caller_id: str = Depends(require_broker_token)):
    verify_ownership(container_id, caller_id)
    await docker_proxy.remove_container(container_id)
    # Cleanup ownership
    if container_id in container_ownership:
        del container_ownership[container_id]
    return {"status": "removed"}

@router.get("/whitelist")
async def get_whitelist(caller_id: str = Depends(require_broker_token)):
    return {"allowed_images": ALLOWED_IMAGES}
